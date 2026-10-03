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
  const scanErrorAlert = document.getElementById('scan-error-alert');

  const resultsPanel = document.getElementById('results-panel');
  const resultsBody = document.getElementById('results-body');
  const resultsSearch = document.getElementById('results-search-input');
  const resultsEmpty = document.getElementById('results-empty');
  const resultsEmptyMsg = document.getElementById('results-empty-msg');
  const resultsCount = document.getElementById('results-count');
  const btnExport = document.getElementById('btn-export-csv');
  const btnCopy = document.getElementById('btn-copy-results');

  const noOpenPortsAlert = document.getElementById('no-open-ports-alert');
  const summaryTarget = document.getElementById('summary-target');
  const summaryScanned = document.getElementById('summary-scanned');
  const summaryOpen = document.getElementById('summary-open');
  const summaryDuration = document.getElementById('summary-duration');

  const countAll = document.getElementById('count-all');
  const countOpen = document.getElementById('count-open');
  const countClosed = document.getElementById('count-closed');
  const countFiltered = document.getElementById('count-filtered');
  const filterBtnFiltered = document.getElementById('filter-btn-filtered');

  let allScannedPorts = [];
  let currentFilteredRows = [];
  let activeStatusFilter = 'all';
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
    if (scanErrorAlert) {
      scanErrorAlert.style.display = 'none';
      scanErrorAlert.textContent = '';
    }
    if (noOpenPortsAlert) {
      noOpenPortsAlert.style.display = 'none';
    }
    resultsPanel.style.display = 'none';
    allScannedPorts = [];
    currentFilteredRows = [];

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
      if (scanErrorAlert) {
        scanErrorAlert.textContent = err.message || 'Failed to start scan.';
        scanErrorAlert.style.display = 'block';
      }
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
          if (scanErrorAlert) {
            scanErrorAlert.textContent = res.error || 'Scan failed. Please verify your target and try again.';
            scanErrorAlert.style.display = 'block';
          }
          stopScanningState();
        } else if (res.status === 'cancelled') {
          stopTimers();
          Toast.show('Scan cancelled.', 'info');
          stopScanningState();
        }
      } catch (err) {
        stopTimers();
        Toast.show(err.message, 'error');
        if (scanErrorAlert) {
          scanErrorAlert.textContent = err.message || 'Error communicating with scanner backend.';
          scanErrorAlert.style.display = 'block';
        }
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

  function updateFilterButtonUI() {
    document.querySelectorAll('.results-filter-buttons [data-status-filter]').forEach((btn) => {
      btn.classList.toggle('active', btn.dataset.statusFilter === activeStatusFilter);
    });
  }

  document.querySelectorAll('.results-filter-buttons [data-status-filter]').forEach((btn) => {
    btn.addEventListener('click', () => {
      activeStatusFilter = btn.dataset.statusFilter;
      updateFilterButtonUI();
      renderResults();
    });
  });

  function onScanComplete(res) {
    stopScanningState();
    if (scanErrorAlert) scanErrorAlert.style.display = 'none';

    const result = res.result || {};
    const openCount = (result.open_ports || []).length;
    Toast.show(`Scan complete — ${openCount} open port(s) found.`, 'success');

    // Extract all scanned ports
    if (result.scanned_ports && Array.isArray(result.scanned_ports)) {
      allScannedPorts = result.scanned_ports.map((p) => ({
        port: Number(p.port),
        service: p.service || 'Unknown',
        state: (p.state || 'closed').toLowerCase(),
        status: (p.status || p.state || 'CLOSED').toUpperCase(),
      }));
    } else if (result.open_ports && Array.isArray(result.open_ports)) {
      allScannedPorts = result.open_ports.map((p) => ({
        port: Number(p.port),
        service: p.service || 'Unknown',
        state: (p.state || 'open').toLowerCase(),
        status: (p.status || p.state || 'OPEN').toUpperCase(),
      }));
    } else {
      allScannedPorts = [];
    }

    lastDbScanId = res.db_scan_id;
    if (btnExport) btnExport.dataset.scanId = lastDbScanId;

    // Update Summary Header Chips
    if (summaryTarget) summaryTarget.textContent = res.target || res.resolved_ip || result.target_ip || '—';
    if (summaryScanned) summaryScanned.textContent = result.total_scanned || res.total || allScannedPorts.length;
    if (summaryOpen) summaryOpen.textContent = openCount;
    if (summaryDuration) summaryDuration.textContent = `${result.duration_seconds || 0}s`;

    // Filter counts
    const numOpen = allScannedPorts.filter((p) => p.status === 'OPEN').length;
    const numClosed = allScannedPorts.filter((p) => p.status === 'CLOSED').length;
    const numFiltered = allScannedPorts.filter((p) => p.status === 'FILTERED' || p.status === 'ERROR').length;

    if (countAll) countAll.textContent = allScannedPorts.length;
    if (countOpen) countOpen.textContent = numOpen;
    if (countClosed) countClosed.textContent = numClosed;
    if (countFiltered) countFiltered.textContent = numFiltered;

    if (filterBtnFiltered) {
      filterBtnFiltered.style.display = numFiltered > 0 ? 'inline-flex' : 'none';
    }

    // Requirement 10: "Agar koi port open nahi hai, 'No open ports found' dikhao, lekin scanned-port results hide mat karo."
    if (noOpenPortsAlert) {
      noOpenPortsAlert.style.display = openCount === 0 ? 'block' : 'none';
    }

    activeStatusFilter = 'all';
    updateFilterButtonUI();

    resultsPanel.style.display = 'block';
    renderResults();
    refreshDashboardStats();
  }

  // -------------------------------------------------------------
  // Results table: search, sort, render
  // -------------------------------------------------------------
  function getStatusPill(status, state) {
    const s = (status || state || 'CLOSED').toUpperCase();
    if (s === 'OPEN') {
      return '<span class="pill pill-open"><span class="pill-dot pulse"></span>OPEN</span>';
    } else if (s === 'FILTERED') {
      return '<span class="pill pill-filtered"><span class="pill-dot"></span>FILTERED</span>';
    } else if (s === 'ERROR') {
      return '<span class="pill pill-error"><span class="pill-dot"></span>ERROR</span>';
    }
    return '<span class="pill pill-closed"><span class="pill-dot"></span>CLOSED</span>';
  }

  function escapeHtml(str) {
    if (!str) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  function renderResults() {
    let rows = [...allScannedPorts];

    // Status Filter
    if (activeStatusFilter === 'open') {
      rows = rows.filter((r) => r.status === 'OPEN');
    } else if (activeStatusFilter === 'closed') {
      rows = rows.filter((r) => r.status === 'CLOSED');
    } else if (activeStatusFilter === 'filtered') {
      rows = rows.filter((r) => r.status === 'FILTERED' || r.status === 'ERROR');
    }

    // Search query (matches port, service, or status)
    const q = (resultsSearch.value || '').toLowerCase().trim();
    if (q) {
      rows = rows.filter(
        (r) =>
          String(r.port).includes(q) ||
          r.service.toLowerCase().includes(q) ||
          r.status.toLowerCase().includes(q)
      );
    }

    // Sort
    rows.sort((a, b) => {
      let av = a[sortState.key];
      let bv = b[sortState.key];
      if (typeof av === 'string') {
        return av.localeCompare(bv) * sortState.dir;
      }
      return (av - bv) * sortState.dir;
    });

    currentFilteredRows = rows;

    // Update sort header icons
    ['port', 'status', 'service'].forEach((col) => {
      const icon = document.getElementById(`sort-icon-${col}`);
      if (icon) {
        if (sortState.key === col) {
          icon.className = `fa-solid ${sortState.dir === 1 ? 'fa-sort-up' : 'fa-sort-down'}`;
        } else {
          icon.className = 'fa-solid fa-sort';
        }
      }
    });

    if (q || activeStatusFilter !== 'all') {
      resultsCount.textContent = `Showing ${rows.length} of ${allScannedPorts.length} scanned ports`;
    } else {
      resultsCount.textContent = `${rows.length} port${rows.length !== 1 ? 's' : ''} scanned`;
    }

    if (!rows.length) {
      resultsBody.innerHTML = '';
      if (resultsEmptyMsg) {
        if (allScannedPorts.length === 0) {
          resultsEmptyMsg.textContent = 'No scan results available.';
        } else if (q) {
          resultsEmptyMsg.textContent = 'No scanned ports match your search query.';
        } else {
          resultsEmptyMsg.textContent = `No ${activeStatusFilter.toUpperCase()} ports found.`;
        }
      }
      resultsEmpty.style.display = 'block';
      return;
    }
    resultsEmpty.style.display = 'none';

    resultsBody.innerHTML = rows
      .map(
        (r) => `
        <tr class="row-in">
          <td style="font-weight:600; font-family:var(--font-mono);">${r.port}</td>
          <td>${getStatusPill(r.status, r.state)}</td>
          <td style="color:var(--text-secondary);">${escapeHtml(r.service)}</td>
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
    const dataToCopy = currentFilteredRows.length ? currentFilteredRows : allScannedPorts;
    if (!dataToCopy.length) {
      Toast.show('No scan results to copy.', 'info');
      return;
    }
    const header = 'Port\tStatus\tService';
    const text = dataToCopy.map((r) => `${r.port}\t${r.status}\t${r.service}`).join('\n');
    const fullText = `${header}\n${text}`;

    if (navigator.clipboard && navigator.clipboard.writeText) {
      try {
        await navigator.clipboard.writeText(fullText);
        Toast.show(`Copied ${dataToCopy.length} port result(s) to clipboard.`, 'success');
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
      Toast.show(`Copied ${dataToCopy.length} port result(s) to clipboard.`, 'success');
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
