/**
 * history.js
 * Drives the Scan History page: fetch + render paginated scan records,
 * search, per-row delete, clear-all, and CSV export links.
 */
(function () {
  const listEl = document.getElementById('history-list');
  if (!listEl) return; // Not on the history page

  const searchInput = document.getElementById('history-search');
  const paginationEl = document.getElementById('history-pagination');
  const emptyState = document.getElementById('history-empty');
  const clearAllBtn = document.getElementById('btn-clear-history');

  let currentPage = 1;
  let searchTimer = null;

  async function loadHistory(page = 1) {
    currentPage = page;
    const q = encodeURIComponent(searchInput.value.trim());
    try {
      const res = await apiRequest(`/api/history?page=${page}&search=${q}`);
      renderList(res.data);
    } catch (err) {
      Toast.show(err.message, 'error');
    }
  }

  function renderList(data) {
    if (!data.items.length) {
      listEl.innerHTML = '';
      emptyState.style.display = 'block';
      paginationEl.innerHTML = '';
      return;
    }
    emptyState.style.display = 'none';

    listEl.innerHTML = data.items
      .map(
        (scan, i) => `
      <div class="glass-card history-row row-in" style="animation-delay:${i * 40}ms">
        <div>
          <span class="sub-label">Target</span>
          <div class="target">${escapeHtml(scan.target)}</div>
        </div>
        <div>
          <span class="sub-label">Port Range</span>
          <div>${scan.start_port}–${scan.end_port}</div>
        </div>
        <div>
          <span class="sub-label">Open Ports</span>
          <div style="color:var(--signal-green)">${scan.open_ports_count}</div>
        </div>
        <div>
          <span class="sub-label">Duration</span>
          <div>${scan.duration_seconds}s</div>
        </div>
        <div>
          <span class="sub-label">Scanned</span>
          <div>${formatDate(scan.created_at)}</div>
        </div>
        <div class="history-actions-cell">
          <a class="icon-btn" href="/api/history/${scan.id}/export" title="Export CSV" aria-label="Export CSV">
            <i class="fa-solid fa-download"></i>
          </a>
          <button class="icon-btn danger" title="Delete" aria-label="Delete scan" onclick="HistoryPage.deleteScan(${scan.id})">
            <i class="fa-solid fa-trash"></i>
          </button>
        </div>
      </div>`
      )
      .join('');

    renderPagination(data);
  }

  function renderPagination(data) {
    if (data.total_pages <= 1) {
      paginationEl.innerHTML = '';
      return;
    }
    let html = '';
    for (let p = 1; p <= data.total_pages; p++) {
      html += `<button class="page-btn ${p === data.page ? 'active' : ''}" onclick="HistoryPage.goToPage(${p})">${p}</button>`;
    }
    paginationEl.innerHTML = html;
  }

  function formatDate(iso) {
    if (!iso) return '—';
    const s = iso.endsWith('Z') ? iso : iso + 'Z';
    const d = new Date(s);
    if (isNaN(d.getTime())) return iso;
    return d.toLocaleString(undefined, {
      month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit',
    });
  }

  function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
  }

  async function deleteScan(id) {
    if (!confirm('Delete this scan record permanently?')) return;
    try {
      await apiRequest(`/api/history/${id}`, { method: 'DELETE' });
      Toast.show('Scan record deleted.', 'success');
      loadHistory(currentPage);
    } catch (err) {
      Toast.show(err.message, 'error');
    }
  }

  clearAllBtn.addEventListener('click', async () => {
    if (!confirm('Clear ALL scan history? This cannot be undone.')) return;
    try {
      await apiRequest('/api/history', { method: 'DELETE' });
      Toast.show('History cleared.', 'success');
      loadHistory(1);
    } catch (err) {
      Toast.show(err.message, 'error');
    }
  });

  searchInput.addEventListener('input', () => {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(() => loadHistory(1), 350);
  });

  window.HistoryPage = { deleteScan, goToPage: loadHistory };
  loadHistory(1);
})();
