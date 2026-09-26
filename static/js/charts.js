/**
 * charts.js
 * Renders Chart.js visualizations on the Home page using aggregate
 * statistics pulled from /api/stats.
 */
(function () {
  const canvas = document.getElementById('home-stats-chart');
  if (!canvas || typeof Chart === 'undefined') return;

  async function render() {
    let stats;
    try {
      const res = await apiRequest('/api/stats');
      stats = res.data;
    } catch {
      stats = { total_open_ports: 0, total_closed_ports: 0 };
    }

    document.querySelectorAll('[data-stat]').forEach((el) => {
      const key = el.dataset.stat;
      if (stats[key] !== undefined && stats[key] !== null) {
        el.textContent = stats[key];
      }
    });
    if (stats.last_scan) {
      const lastEl = document.querySelector('[data-stat="last_scan_target"]');
      if (lastEl) lastEl.textContent = stats.last_scan.target;
    }

    Chart.defaults.color = '#8fb5ac';
    Chart.defaults.font.family = "'JetBrains Mono', monospace";

    const existingChart = Chart.getChart(canvas);
    if (existingChart) existingChart.destroy();

    new Chart(canvas, {
      type: 'doughnut',
      data: {
        labels: ['Open Ports', 'Closed Ports'],
        datasets: [
          {
            data: [stats.total_open_ports || 0, stats.total_closed_ports || 1],
            backgroundColor: ['rgba(0, 255, 157, 0.85)', 'rgba(255, 47, 126, 0.55)'],
            borderColor: '#05080a',
            borderWidth: 3,
            hoverOffset: 8,
          },
        ],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        cutout: '68%',
        plugins: {
          legend: { position: 'bottom', labels: { boxWidth: 12, padding: 18 } },
          tooltip: {
            backgroundColor: '#0a1818',
            borderColor: 'rgba(0,255,157,0.3)',
            borderWidth: 1,
          },
        },
      },
    });
  }

  render();
})();
