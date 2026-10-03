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
  window.hideLoader = dismissLoader;
  const fallbackTimer = setTimeout(hideLoader, MAX_LOADER_TIMEOUT);

  function scheduleDismiss() {
    clearTimeout(fallbackTimer);
    setTimeout(hideLoader, prefersReducedMotion ? 0 : 180);
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

// ---------------------------------------------------------------------
// Authentication Modal (Popup) Controller
// ---------------------------------------------------------------------
(function initAuthModal() {
  const backdrop = document.getElementById('auth-modal-backdrop');
  if (!backdrop) return;

  const loginView = document.getElementById('auth-modal-login');
  const signupView = document.getElementById('auth-modal-signup');
  const loginError = document.getElementById('auth-modal-login-error');
  const signupError = document.getElementById('auth-modal-signup-error');

  function closeMobileNavIfOpen() {
    const navLinks = document.getElementById('nav-links');
    const navToggle = document.getElementById('nav-toggle');
    if (navLinks && navLinks.classList.contains('open')) {
      navLinks.classList.remove('open');
    }
    if (navToggle && navToggle.classList.contains('open')) {
      navToggle.classList.remove('open');
      navToggle.setAttribute('aria-expanded', 'false');
    }
  }

  function openModal(viewName) {
    if (!backdrop) return;
    closeMobileNavIfOpen();

    if (viewName === 'signup') {
      if (loginView) loginView.style.display = 'none';
      if (signupView) signupView.style.display = 'block';
      setTimeout(() => {
        const firstInput = signupView ? signupView.querySelector('input:not([type="hidden"])') : null;
        if (firstInput) firstInput.focus();
      }, 60);
    } else {
      if (signupView) signupView.style.display = 'none';
      if (loginView) loginView.style.display = 'block';
      setTimeout(() => {
        const firstInput = loginView ? loginView.querySelector('input:not([type="hidden"])') : null;
        if (firstInput) firstInput.focus();
      }, 60);
    }

    backdrop.classList.add('open');
    backdrop.setAttribute('aria-hidden', 'false');
    document.body.classList.add('modal-open');
  }

  function closeModal() {
    if (!backdrop) return;
    backdrop.classList.remove('open');
    backdrop.setAttribute('aria-hidden', 'true');
    document.body.classList.remove('modal-open');
    if (loginError) { loginError.style.display = 'none'; loginError.textContent = ''; }
    if (signupError) { signupError.style.display = 'none'; signupError.textContent = ''; }
  }

  // Intercept clicks on links/buttons with [data-auth-modal]
  document.querySelectorAll('[data-auth-modal]').forEach((trigger) => {
    trigger.addEventListener('click', (e) => {
      if (e.metaKey || e.ctrlKey || e.shiftKey || e.button === 1) return;
      e.preventDefault();
      const target = trigger.getAttribute('data-auth-modal');
      openModal(target);
    });
  });

  // Switch between Login and Sign Up views inside the modal
  document.querySelectorAll('[data-auth-switch]').forEach((btn) => {
    btn.addEventListener('click', (e) => {
      e.preventDefault();
      const target = btn.getAttribute('data-auth-switch');
      if (loginError) { loginError.style.display = 'none'; loginError.textContent = ''; }
      if (signupError) { signupError.style.display = 'none'; signupError.textContent = ''; }
      openModal(target);
    });
  });

  // Close buttons (X)
  document.querySelectorAll('[data-auth-close]').forEach((btn) => {
    btn.addEventListener('click', (e) => {
      e.preventDefault();
      closeModal();
    });
  });

  // Close when clicking outside the modal content (on the dark backdrop)
  backdrop.addEventListener('click', (e) => {
    if (e.target === backdrop) {
      closeModal();
    }
  });

  // Close on Escape key press
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && backdrop.classList.contains('open')) {
      closeModal();
    }
  });

  // AJAX submission helper that reuses existing backend routes and handles redirects & errors
  function setupAjaxAuthForm(form, errorEl, submitBtn, defaultHtml) {
    if (!form || !errorEl || !submitBtn) return;

    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      errorEl.style.display = 'none';
      errorEl.textContent = '';

      submitBtn.disabled = true;
      submitBtn.innerHTML = '<i class="fa-solid fa-circle-notch fa-spin"></i> Processing...';

      const formData = new FormData(form);
      const action = form.getAttribute('action') || window.location.href;

      try {
        const response = await fetch(action, {
          method: 'POST',
          body: formData,
          headers: {
            'X-Requested-With': 'XMLHttpRequest'
          }
        });

        // Backend redirected on success (e.g. 302 to /dashboard)
        if (response.redirected) {
          window.location.href = response.url;
          return;
        }

        // Parse HTML response (render_template on error or same page)
        const html = await response.text();
        const parser = new DOMParser();
        const doc = parser.parseFromString(html, 'text/html');

        // Look for flash message in the returned response
        const flashMsg = doc.querySelector('.flash-message.error, .flash-message');
        if (flashMsg && flashMsg.textContent.trim()) {
          errorEl.textContent = flashMsg.textContent.trim();
          errorEl.style.display = 'block';
          submitBtn.disabled = false;
          submitBtn.innerHTML = defaultHtml;

          // Clear password input on error
          const pwdInput = form.querySelector('input[type="password"]');
          if (pwdInput) {
            pwdInput.value = '';
            pwdInput.focus();
          }
          return;
        }

        // If returned page indicates dashboard/authenticated state
        if (html.includes('scanner dashboard') || html.includes('Network Port Scanner')) {
          window.location.href = '/dashboard';
          return;
        }

        if (response.status >= 400) {
          errorEl.textContent = 'Authentication failed. Please verify your details.';
          errorEl.style.display = 'block';
        } else {
          // If 200 without error message, navigate to dashboard
          window.location.href = '/dashboard';
          return;
        }
      } catch (err) {
        // Fallback to standard form submission if fetch encounters a network error
        form.submit();
        return;
      }

      submitBtn.disabled = false;
      submitBtn.innerHTML = defaultHtml;
    });
  }

  const loginForm = document.getElementById('modal-login-form');
  const loginSubmit = document.getElementById('modal-login-submit');
  setupAjaxAuthForm(loginForm, loginError, loginSubmit, '<i class="fa-solid fa-right-to-bracket"></i> Log In');

  const signupForm = document.getElementById('modal-signup-form');
  const signupSubmit = document.getElementById('modal-signup-submit');
  setupAjaxAuthForm(signupForm, signupError, signupSubmit, '<i class="fa-solid fa-user-plus"></i> Create Account');

  window.openAuthModal = openModal;
  window.closeAuthModal = closeModal;
})();

