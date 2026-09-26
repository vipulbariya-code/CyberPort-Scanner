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
  const cancelBtn = document.getElementById('cancel-btn');
  const authorizationInput = document.getElementById('authorization-input');

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
  const resultsEmptyMsg = document.getElementById('results-empty-msg');
  const resultsCount = document.getElementById('results-count');
  const btnExport = document.getElementById('btn-export-csv');
  const btnCopy = document.getElementById('btn-copy-results');

  let currentResults = [];
  let sortState = { key: 'port', dir: 1 };
  let pollTimer = null;
  let elapsedTimer = null;
  let scanStartTime = null;
  let lastDbScanId = null;
  let currentJobId = null;

  // -------------------------------------------------------------
  // Validation
  // -------------------------------------------------------------
  const IPV4_RE = /^(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)){3}$/;
  const HOSTNAME_RE = /^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$/;

  function validateTarget(value) {
    let v = (value || '').trim();
    if (!v) return 'Target is required.';
    if (v.toLowerCase().startsWith('http://')) v = v.slice(7);
    if (v.toLowerCase().startsWith('https://')) v = v.slice(8);
    v = v.split('/')[0].split('?')[0].split(':')[0].trim();
    if (!v) return 'Target is required.';
    if (!IPV4_RE.test(v) && !HOSTNAME_RE.test(v)) {
      return 'Enter a valid IPv4 address or domain name.';
    }
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
    if (errEl) errEl.textContent = msg;
    if (el) el.classList.toggle('invalid', Boolean(msg));
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
      setFieldError(endPortInput, portError, '');
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
    if (!authorizationInput.checked) {
      Toast.show('Confirm that you are authorized to scan this target.', 'error');
      return;
    }

    scanBtn.disabled = true;
    scanBtn.innerHTML = '<i class="fa-solid fa-spinner spin"></i> Scanning...';
    if (cancelBtn) {
      cancelBtn.style.display = 'inline-flex';
      cancelBtn.disabled = false;
      cancelBtn.innerHTML = '<i class="fa-solid fa-stop"></i> Cancel';
    }
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
          authorized: authorizationInput.checked,
        }),
      });
      currentJobId = res.job_id;
      scanStartTime = Date.now();
      progressWrap.classList.add('active');
      startElapsedTimer();
      pollStatus(res.job_id);
      Toast.show(`Scan started on ${res.resolved_ip} — ${res.total_ports} ports queued.`, 'info');
    } catch (err) {
      Toast.show(err.message, 'error');
      stopScanningState();
    }
  });

  if (cancelBtn) {
    cancelBtn.addEventListener('click', async () => {
      if (!currentJobId) return;
      cancelBtn.disabled = true;
      cancelBtn.innerHTML = '<i class="fa-solid fa-spinner spin"></i> Cancelling...';
      try {
        await apiRequest(`/api/scan/cancel/${currentJobId}`, { method: 'POST' });
        Toast.show('Scan cancelled.', 'info');
      } catch (err) {
        Toast.show(err.message, 'error');
      } finally {
        stopScanningState();
      }
    });
  }

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
          stopTimers();
          onScanComplete(res);
        } else if (res.status === 'error') {
          stopTimers();
          Toast.show(res.error || 'Scan failed.', 'error');
          stopScanningState();
        } else if (res.status === 'cancelled') {
          stopTimers();
          Toast.show('Scan cancelled.', 'info');
          stopScanningState();
        }
      } catch (err) {
        stopTimers();
        Toast.show(err.message, 'error');
        stopScanningState();
      }
    }, 400);
  }

  function stopTimers() {
    if (pollTimer) clearInterval(pollTimer);
    if (elapsedTimer) clearInterval(elapsedTimer);
  }

  function stopScanningState() {
    stopTimers();
    currentJobId = null;
    scanBtn.disabled = false;
    scanBtn.innerHTML = '<i class="fa-solid fa-bolt"></i> Start Scan';
    if (cancelBtn) cancelBtn.style.display = 'none';
    scanPanel.classList.remove('scanning');
  }

  // Cleanup timers on unload
  window.addEventListener('beforeunload', stopTimers);
  window.addEventListener('pagehide', stopTimers);

  function updateProgress(res) {
    const pct = res.total ? Math.min(100, Math.round((res.scanned / res.total) * 100)) : 0;
    progressFill.style.width = `${pct}%`;
    progressScanned.textContent = `${res.scanned} / ${res.total} (${pct}%)`;
    progressOpen.textContent = res.open_count;
  }

  function onScanComplete(res) {
    stopScanningState();
    Toast.show(`Scan complete — ${res.result.open_ports.length} open port(s) found.`, 'success');

    currentResults = res.result.open_ports.map((p) => ({ ...p }));
    lastDbScanId = res.db_scan_id;
    resultsPanel.style.display = 'block';
    if (btnExport) btnExport.dataset.scanId = lastDbScanId;
    renderResults();
    refreshDashboardStats();
  }

  // -------------------------------------------------------------
  // Results table: search, sort
  // -------------------------------------------------------------
  function renderResults() {
    let rows = [...currentResults];

    const q = (resultsSearch.value || '').toLowerCase().trim();
    if (q) {
      rows = rows.filter(
        (r) => String(r.port).includes(q) || r.service.toLowerCase().includes(q)
      );
    }

    rows.sort((a, b) => {
      let av = a[sortState.key];
      let bv = b[sortState.key];
      if (typeof av === 'string') {
        return av.localeCompare(bv) * sortState.dir;
      }
      return (av - bv) * sortState.dir;
    });

    // Update sort header icons
    ['port', 'service', 'state'].forEach((col) => {
      const icon = document.getElementById(`sort-icon-${col}`);
      if (icon) {
        if (sortState.key === col) {
          icon.className = `fa-solid ${sortState.dir === 1 ? 'fa-sort-up' : 'fa-sort-down'}`;
        } else {
          icon.className = 'fa-solid fa-sort';
        }
      }
    });

    if (q) {
      resultsCount.textContent = `Showing ${rows.length} of ${currentResults.length} open ports`;
    } else {
      resultsCount.textContent = `${rows.length} open port${rows.length !== 1 ? 's' : ''} found`;
    }

    if (!rows.length) {
      resultsBody.innerHTML = '';
      if (resultsEmptyMsg) {
        if (currentResults.length === 0) {
          resultsEmptyMsg.textContent = 'No open ports detected in this range (all scanned ports closed or filtered).';
        } else {
          resultsEmptyMsg.textContent = 'No open ports match your search query.';
        }
      }
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
    if (!lastDbScanId) {
      Toast.show('No scan record available for export.', 'info');
      return;
    }
    window.location.href = `/api/history/${lastDbScanId}/export`;
  });

  btnCopy.addEventListener('click', async () => {
    if (!currentResults.length) {
      Toast.show('No open port results to copy.', 'info');
      return;
    }
    const header = 'Port\tService\tState';
    const text = currentResults.map((r) => `${r.port}\t${r.service}\t${r.state}`).join('\n');
    const fullText = `${header}\n${text}`;

    if (navigator.clipboard && navigator.clipboard.writeText) {
      try {
        await navigator.clipboard.writeText(fullText);
        Toast.show('Results copied to clipboard.', 'success');
        return;
      } catch {
        // Fallback below
      }
    }

    // Fallback for older browsers or non-secure contexts
    const ta = document.createElement('textarea');
    ta.value = fullText;
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    try {
      document.execCommand('copy');
      Toast.show('Results copied to clipboard.', 'success');
    } catch {
      Toast.show('Could not copy — clipboard access denied.', 'error');
    } finally {
      ta.remove();
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
