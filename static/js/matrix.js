/**
 * matrix.js
 * Renders an animated "digital rain" background on a full-viewport canvas.
 * Pure decorative layer — respects prefers-reduced-motion.
 */
(function () {
  const canvas = document.getElementById('matrix-canvas');
  if (!canvas) return;

  const ctx = canvas.getContext('2d');
  const reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  const CHARS = 'アイウエオカキクケコサシスセソ01アイウエオ<>[]{}#$%&';
  const FONT_SIZE = 15;
  let columns = [];
  let width, height;

  function resize() {
    width = canvas.width = window.innerWidth;
    height = canvas.height = window.innerHeight;
    const colCount = Math.floor(width / FONT_SIZE);
    columns = new Array(colCount).fill(0).map(() => Math.floor(Math.random() * -50));
  }

  function draw() {
    ctx.fillStyle = 'rgba(5, 8, 10, 0.08)';
    ctx.fillRect(0, 0, width, height);

    ctx.font = `${FONT_SIZE}px 'JetBrains Mono', monospace`;

    for (let i = 0; i < columns.length; i++) {
      const char = CHARS[Math.floor(Math.random() * CHARS.length)];
      const x = i * FONT_SIZE;
      const y = columns[i] * FONT_SIZE;

      // Leading character brighter (cyan), trailing green
      const isLead = Math.random() > 0.94;
      ctx.fillStyle = isLead ? 'rgba(120, 255, 220, 0.9)' : 'rgba(0, 255, 157, 0.35)';
      ctx.fillText(char, x, y);

      if (y > height && Math.random() > 0.975) {
        columns[i] = 0;
      } else {
        columns[i]++;
      }
    }
  }

  resize();
  window.addEventListener('resize', resize);

  if (!reduceMotion) {
    setInterval(draw, 45);
  } else {
    // Static faint frame only
    ctx.fillStyle = 'rgba(5,8,10,1)';
    ctx.fillRect(0, 0, width, height);
  }
})();
