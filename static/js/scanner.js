/**
 * scanner.js
 * Drives the Scanner Dashboard page: input validation, launching a scan,
 * polling live progress, and rendering a searchable/sortable results table.
 */
(function () {
  const form = document.getElementById('scan-form');
  if (!form) return; // Not on the dashboard page

  const targetInput = document.getElementById('target-input');
  const startPortInput = document.getElementById('start-port-input');
  const endPortInput = document.getElementById('end-port-input');
  const targetError = document.getElementById('target-error');
  const portError = document.getElementById('port-error');
  const scanBtn = document.getElementById('scan-btn');

  const progressWrap = document.getElementById('scan-progress-wrap');
  const progressFill = document.getElementById('progress-fill');
  const progressScanned = document.getElementById('progress-scanned');
  const progressElapsed = document.getElementById('progress-elapsed');
  const progressOpen = document.getElementById('progress-open');
  const scanPanel = document.getElementById('scan-panel');

  const resultsPanel = document.getElementById('results-panel');
  const resultsBody = document.getElementById('results-body');
  const resultsSearch = document.getElementById('results-search-input');
  const resultsEmpty = document.getElementById('results-empty');
  const resultsCount = document.getElementById('results-count');
  const btnExport = document.getElementById('btn-export-csv');
  const btnCopy = document.getElementById('btn-copy-results');
  const filterTabs = document.querySelectorAll('.filter-tab');

  let currentResults = [];
  let currentFilter = 'all';
  let sortState = { key: 'port', dir: 1 };
  let pollTimer = null;
  let elapsedTimer = null;
  let scanStartTime = null;
  let lastDbScanId = null;

  // -------------------------------------------------------------
  // Validation
  // -------------------------------------------------------------
  const IPV4_RE = /^(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)){3}$/;
  const HOSTNAME_RE = /^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$/;

  function validateTarget(value) {
    const v = value.trim();
    if (!v) return 'Target is required.';
    if (!IPV4_RE.test(v) && !HOSTNAME_RE.test(v)) return 'Enter a valid IPv4 address or domain name.';
    return '';
  }

  function validatePorts(start, end) {
    const s = Number(start), e = Number(end);
    if (!start || !end) return 'Both start and end ports are required.';
    if (!Number.isInteger(s) || !Number.isInteger(e)) return 'Ports must be whole numbers.';
    if (s < 1 || s > 65535 || e < 1 || e > 65535) return 'Ports must be between 1 and 65535.';
    if (s > e) return 'Start port must be ≤ end port.';
    if (e - s + 1 > 1024) return 'Range too large — max 1024 ports per scan.';
    return '';
  }

  function setFieldError(el, errEl, msg) {
    errEl.textContent = msg;
    el.classList.toggle('invalid', Boolean(msg));
  }

  targetInput.addEventListener('input', () => setFieldError(targetInput, targetError, ''));
  [startPortInput, endPortInput].forEach((el) =>
    el.addEventListener('input', () => setFieldError(endPortInput, portError, ''))
  );

  // -------------------------------------------------------------
  // Preset port ranges
  // -------------------------------------------------------------
  document.querySelectorAll('.preset-chip').forEach((chip) => {
    chip.addEventListener('click', () => {
      const [s, e] = chip.dataset.range.split('-');
      startPortInput.value = s;
      endPortInput.value = e;
    });
  });

  // -------------------------------------------------------------
  // Form submit → start scan
  // -------------------------------------------------------------
  form.addEventListener('submit', async (e) => {
    e.preventDefault();

    const targetErrMsg = validateTarget(targetInput.value);
    const portErrMsg = validatePorts(startPortInput.value, endPortInput.value);
    setFieldError(targetInput, targetError, targetErrMsg);
    setFieldError(endPortInput, portError, portErrMsg);
    if (targetErrMsg || portErrMsg) return;

    scanBtn.disabled = true;
    scanBtn.innerHTML = '<i class="fa-solid fa-spinner spin"></i> Initializing...';
    scanPanel.classList.add('scanning');
    resultsPanel.style.display = 'none';
    currentResults = [];

    try {
      const res = await apiRequest('/api/scan/start', {
        method: 'POST',
        body: JSON.stringify({
          target: targetInput.value.trim(),
          start_port: Number(startPortInput.value),
          end_port: Number(endPortInput.value),
        }),
      });
      scanStartTime = Date.now();
      progressWrap.classList.add('active');
      startElapsedTimer();
      pollStatus(res.job_id);
      Toast.show(`Scan started on ${res.resolved_ip} — ${res.total_ports} ports queued.`, 'info');
    } catch (err) {
      Toast.show(err.message, 'error');
      resetScanButton();
      scanPanel.classList.remove('scanning');
    }
  });

  function startElapsedTimer() {
    clearInterval(elapsedTimer);
    elapsedTimer = setInterval(() => {
      const secs = ((Date.now() - scanStartTime) / 1000).toFixed(1);
      progressElapsed.textContent = `${secs}s`;
    }, 100);
  }

  function pollStatus(jobId) {
    clearInterval(pollTimer);
    pollTimer = setInterval(async () => {
      try {
        const res = await apiRequest(`/api/scan/status/${jobId}`);
        updateProgress(res);
        if (res.status === 'completed') {
          clearInterval(pollTimer);
          clearInterval(elapsedTimer);
          onScanComplete(res);
        } else if (res.status === 'error') {
          clearInterval(pollTimer);
          clearInterval(elapsedTimer);
          Toast.show(res.error || 'Scan failed.', 'error');
          resetScanButton();
          scanPanel.classList.remove('scanning');
        }
      } catch (err) {
        clearInterval(pollTimer);
        clearInterval(elapsedTimer);
        Toast.show(err.message, 'error');
        resetScanButton();
        scanPanel.classList.remove('scanning');
      }
    }, 400);
  }

  function updateProgress(res) {
    const pct = res.total ? Math.min(100, Math.round((res.scanned / res.total) * 100)) : 0;
    progressFill.style.width = `${pct}%`;
    progressScanned.textContent = `${res.scanned} / ${res.total} (${pct}%)`;
    progressOpen.textContent = res.open_count;
  }

  function onScanComplete(res) {
    resetScanButton();
    scanPanel.classList.remove('scanning');
    Toast.show(`Scan complete — ${res.result.open_ports.length} open port(s) found.`, 'success');

    currentResults = buildFullResultSet(res.result);
    lastDbScanId = res.db_scan_id;
    resultsPanel.style.display = 'block';
    btnExport.dataset.scanId = lastDbScanId;
    renderResults();
    refreshDashboardStats();
  }

  function buildFullResultSet(result) {
    // Combine open ports (from scan) with a lightweight closed-port summary line.
    const rows = result.open_ports.map((p) => ({ ...p }));
    return rows;
  }

  function resetScanButton() {
    scanBtn.disabled = false;
    scanBtn.innerHTML = '<i class="fa-solid fa-bolt"></i> Start Scan';
  }

  // -------------------------------------------------------------
  // Results table: search, filter, sort
  // -------------------------------------------------------------
  function renderResults() {
    let rows = [...currentResults];

    const q = (resultsSearch.value || '').toLowerCase().trim();
    if (q) {
      rows = rows.filter(
        (r) => String(r.port).includes(q) || r.service.toLowerCase().includes(q)
      );
    }

    if (currentFilter === 'open') rows = rows.filter((r) => r.state === 'open');

    rows.sort((a, b) => {
      const av = a[sortState.key], bv = b[sortState.key];
      if (av < bv) return -1 * sortState.dir;
      if (av > bv) return 1 * sortState.dir;
      return 0;
    });

    resultsCount.textContent = `${rows.length} result${rows.length !== 1 ? 's' : ''}`;

    if (!rows.length) {
      resultsBody.innerHTML = '';
      resultsEmpty.style.display = 'block';
      return;
    }
    resultsEmpty.style.display = 'none';

    resultsBody.innerHTML = rows
      .map(
        (r, i) => `
        <tr class="row-in" style="animation-delay:${Math.min(i * 25, 400)}ms">
          <td>${r.port}</td>
          <td>${r.service}</td>
          <td><span class="pill pill-open"><span class="pill-dot pulse"></span>OPEN</span></td>
        </tr>`
      )
      .join('');
  }

  resultsSearch.addEventListener('input', renderResults);

  filterTabs.forEach((tab) => {
    tab.addEventListener('click', () => {
      filterTabs.forEach((t) => t.classList.remove('active'));
      tab.classList.add('active');
      currentFilter = tab.dataset.filter;
      renderResults();
    });
  });

  document.querySelectorAll('.results-table th[data-sort]').forEach((th) => {
    th.addEventListener('click', () => {
      const key = th.dataset.sort;
      sortState.dir = sortState.key === key ? -sortState.dir : 1;
      sortState.key = key;
      renderResults();
    });
  });

  // -------------------------------------------------------------
  // Export / Copy
  // -------------------------------------------------------------
  btnExport.addEventListener('click', () => {
    if (!lastDbScanId) return;
    window.location.href = `/api/history/${lastDbScanId}/export`;
  });

  btnCopy.addEventListener('click', async () => {
    if (!currentResults.length) {
      Toast.show('No results to copy yet.', 'info');
      return;
    }
    const text = currentResults.map((r) => `${r.port}\t${r.service}\t${r.state}`).join('\n');
    try {
      await navigator.clipboard.writeText(`Port\tService\tState\n${text}`);
      Toast.show('Results copied to clipboard.', 'success');
    } catch {
      Toast.show('Could not copy — clipboard access denied.', 'error');
    }
  });

  // -------------------------------------------------------------
  // Dashboard widgets (loaded on page init)
  // -------------------------------------------------------------
  async function refreshDashboardStats() {
    try {
      const res = await apiRequest('/api/stats');
      const d = res.data;
      document.getElementById('widget-total-scans').textContent = d.total_scans;
      document.getElementById('widget-open-ports').textContent = d.total_open_ports;
      document.getElementById('widget-closed-ports').textContent = d.total_closed_ports;
      document.getElementById('widget-last-scan').textContent = d.last_scan
        ? d.last_scan.target
        : '—';
      document.getElementById('widget-duration').textContent = d.last_scan
        ? `${d.last_scan.duration_seconds}s`
        : '—';
    } catch (e) {
      /* silent — widgets simply stay at defaults */
    }
  }
  refreshDashboardStats();
})();
