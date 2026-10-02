/**
 * main.js
 * Shared UI behavior used across every page: loading screen, mobile nav,
 * toast notifications, scroll-reveal animations, FAQ accordion, and the
 * hero typing effect.
 */

// ---------------------------------------------------------------------
// Loading screen (graceful, non-blocking with safe fallback)
// ---------------------------------------------------------------------
(function initLoadingScreen() {
  const loader = document.getElementById('loading-screen');
  if (!loader) return;

  let isDismissed = false;
  const prefersReducedMotion =
    typeof window.matchMedia === 'function' &&
    window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  function dismissLoader() {
    if (isDismissed) return;
    isDismissed = true;

    if (prefersReducedMotion) {
      loader.classList.add('hidden');
      loader.style.display = 'none';
      return;
    }

    loader.classList.add('hidden');
    // Remove from render tree after transition finishes
    setTimeout(() => {
      if (loader) {
        loader.style.display = 'none';
      }
    }, 450);
  }

  // Safe fallback timeout: dismiss after 1.5s max regardless of external resources
  const MAX_LOADER_TIMEOUT = 1500;
  const fallbackTimer = setTimeout(dismissLoader, MAX_LOADER_TIMEOUT);

  function scheduleDismiss() {
    clearTimeout(fallbackTimer);
    setTimeout(dismissLoader, prefersReducedMotion ? 0 : 180);
  }

  if (document.readyState === 'complete') {
    clearTimeout(fallbackTimer);
    dismissLoader();
  } else if (document.readyState === 'interactive') {
    scheduleDismiss();
  } else {
    document.addEventListener('DOMContentLoaded', scheduleDismiss, { once: true });
    window.addEventListener('load', () => {
      clearTimeout(fallbackTimer);
      dismissLoader();
    }, { once: true });
  }

  window.dismissCyberPortLoader = dismissLoader;
})();

// ---------------------------------------------------------------------
// Mobile nav toggle
// ---------------------------------------------------------------------
(function initNav() {
  const toggle = document.getElementById('nav-toggle');
  const links = document.getElementById('nav-links');
  if (!toggle || !links) return;
  toggle.addEventListener('click', () => {
    const isOpen = links.classList.toggle('open');
    toggle.classList.toggle('open', isOpen);
    toggle.setAttribute('aria-expanded', isOpen ? 'true' : 'false');
  });
  links.querySelectorAll('a').forEach((a) =>
    a.addEventListener('click', () => {
      links.classList.remove('open');
      toggle.classList.remove('open');
      toggle.setAttribute('aria-expanded', 'false');
    })
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
// Active nav link highlighting
// ---------------------------------------------------------------------
(function highlightNav() {
  const path = window.location.pathname;
  document.querySelectorAll('.nav-link').forEach((link) => {
    const href = link.getAttribute('href');
    if (!href) return;
    if (href === path || (href !== '/' && path.startsWith(href))) {
      link.classList.add('active');
    }
  });
})();

// ---------------------------------------------------------------------
// Small fetch helper with CSRF token support and consistent error surfacing
// ---------------------------------------------------------------------
async function apiRequest(url, options = {}) {
  const csrfMeta = document.querySelector('meta[name="csrf-token"]');
  const csrfToken = csrfMeta ? csrfMeta.getAttribute('content') : '';

  const headers = {
    'Content-Type': 'application/json',
    ...(csrfToken ? { 'X-CSRF-Token': csrfToken } : {}),
    ...(options.headers || {}),
  };

  try {
    const res = await fetch(url, {
      ...options,
      headers,
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

// ---------------------------------------------------------------------
// Code Showcase Tabs & Copy to Clipboard
// ---------------------------------------------------------------------
(function initCodeShowcase() {
  document.querySelectorAll('.api-tab-chip').forEach((tab) => {
    tab.addEventListener('click', () => {
      const targetId = tab.getAttribute('data-tab');
      const container = tab.closest('.api-showcase-box') || document;
      container.querySelectorAll('.api-tab-chip').forEach((t) => t.classList.remove('active'));
      container.querySelectorAll('.api-code-snippet').forEach((c) => c.classList.remove('active'));
      tab.classList.add('active');
      const targetSnippet = document.getElementById(targetId);
      if (targetSnippet) targetSnippet.classList.add('active');
    });
  });

  document.querySelectorAll('.api-copy-btn').forEach((btn) => {
    btn.addEventListener('click', async () => {
      const targetSelector = btn.getAttribute('data-target');
      const codeEl = document.querySelector(targetSelector);
      if (!codeEl) return;
      const text = codeEl.innerText || codeEl.textContent;
      try {
        await navigator.clipboard.writeText(text);
        const originalHtml = btn.innerHTML;
        btn.innerHTML = '<i class="fa-solid fa-check"></i> Copied!';
        setTimeout(() => {
          btn.innerHTML = originalHtml;
        }, 2000);
      } catch (e) {
        if (window.Toast) Toast.show('Copied text fallback', 'info');
      }
    });
  });
})();

