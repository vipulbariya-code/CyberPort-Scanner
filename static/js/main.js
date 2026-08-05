/**
 * main.js
 * Shared UI behavior used across every page: loading screen, mobile nav,
 * toast notifications, scroll-reveal animations, FAQ accordion, and the
 * hero typing effect.
 */

// ---------------------------------------------------------------------
// Loading screen
// ---------------------------------------------------------------------
window.addEventListener('load', () => {
  const loader = document.getElementById('loading-screen');
  if (!loader) return;
  setTimeout(() => loader.classList.add('hidden'), 900);
});

// ---------------------------------------------------------------------
// Mobile nav toggle
// ---------------------------------------------------------------------
(function initNav() {
  const toggle = document.getElementById('nav-toggle');
  const links = document.getElementById('nav-links');
  if (!toggle || !links) return;
  toggle.addEventListener('click', () => {
    links.classList.toggle('open');
    toggle.classList.toggle('open');
  });
  links.querySelectorAll('a').forEach((a) =>
    a.addEventListener('click', () => links.classList.remove('open'))
  );
})();

// ---------------------------------------------------------------------
// Toast notifications
// ---------------------------------------------------------------------
const Toast = {
  container: null,
  init() {
    this.container = document.getElementById('toast-container');
  },
  show(message, type = 'info', duration = 4200) {
    if (!this.container) this.init();
    if (!this.container) return;

    const icons = { success: 'fa-circle-check', error: 'fa-triangle-exclamation', info: 'fa-terminal' };
    const el = document.createElement('div');
    el.className = `toast ${type}`;
    const icon = document.createElement('i');
    icon.className = `fa-solid ${icons[type] || icons.info} toast-icon`;
    const text = document.createElement('span');
    text.textContent = message;
    const close = document.createElement('button');
    close.className = 'toast-close';
    close.setAttribute('aria-label', 'Dismiss notification');
    close.innerHTML = '<i class="fa-solid fa-xmark"></i>';
    el.append(icon, text, close);
    el.querySelector('.toast-close').addEventListener('click', () => this.dismiss(el));
    this.container.appendChild(el);

    setTimeout(() => this.dismiss(el), duration);
  },
  dismiss(el) {
    if (!el || !el.parentNode) return;
    el.classList.add('out');
    setTimeout(() => el.remove(), 300);
  },
};
window.Toast = Toast;

// ---------------------------------------------------------------------
// Scroll reveal
// ---------------------------------------------------------------------
(function initReveal() {
  const items = document.querySelectorAll('.reveal');
  if (!items.length) return;
  const observer = new IntersectionObserver(
    (entries) => {
      entries.forEach((entry) => {
        if (entry.isIntersecting) {
          entry.target.classList.add('in-view');
          observer.unobserve(entry.target);
        }
      });
    },
    { threshold: 0.15 }
  );
  items.forEach((item) => observer.observe(item));
})();

// ---------------------------------------------------------------------
// FAQ accordion
// ---------------------------------------------------------------------
(function initFaq() {
  document.querySelectorAll('.faq-question').forEach((btn) => {
    btn.addEventListener('click', () => {
      const item = btn.closest('.faq-item');
      const wasOpen = item.classList.contains('open');
      document.querySelectorAll('.faq-item.open').forEach((i) => i.classList.remove('open'));
      if (!wasOpen) item.classList.add('open');
    });
  });
})();

// ---------------------------------------------------------------------
// Hero typing effect
// ---------------------------------------------------------------------
(function initTyping() {
  const el = document.getElementById('typed-text');
  if (!el) return;

  const phrases = [
    'Scanning for authorized security research...',
    'Educational network diagnostics, made visual.',
    'Know your own attack surface, ethically.',
    'Built for students, learners & pentesting labs.',
  ];
  let phraseIndex = 0, charIndex = 0, deleting = false;

  function tick() {
    const current = phrases[phraseIndex];
    if (!deleting) {
      charIndex++;
      el.textContent = current.slice(0, charIndex);
      if (charIndex === current.length) {
        deleting = true;
        setTimeout(tick, 1600);
        return;
      }
    } else {
      charIndex--;
      el.textContent = current.slice(0, charIndex);
      if (charIndex === 0) {
        deleting = false;
        phraseIndex = (phraseIndex + 1) % phrases.length;
      }
    }
    setTimeout(tick, deleting ? 28 : 42);
  }
  tick();
})();

// ---------------------------------------------------------------------
// Active nav link highlighting
// ---------------------------------------------------------------------
(function highlightNav() {
  const path = window.location.pathname;
  document.querySelectorAll('.nav-link').forEach((link) => {
    const href = link.getAttribute('href');
    if (href === path || (href !== '/' && path.startsWith(href))) {
      link.classList.add('active');
    }
  });
})();

// ---------------------------------------------------------------------
// Small fetch helper with consistent error surfacing
// ---------------------------------------------------------------------
async function apiRequest(url, options = {}) {
  try {
    const res = await fetch(url, {
      headers: { 'Content-Type': 'application/json', ...(options.headers || {}) },
      ...options,
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok || data.success === false) {
      throw new Error(data.error || `Request failed (${res.status})`);
    }
    return data;
  } catch (err) {
    throw err;
  }
}
window.apiRequest = apiRequest;
