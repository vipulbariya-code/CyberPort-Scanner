/**
 * developer.js
 * ------------
 * Handles Developer API Key generation, masked display, revocation,
 * clipboard copying, and documentation quickstart interactions.
 */

document.addEventListener("DOMContentLoaded", () => {
  const keysTbody = document.getElementById("keys-tbody");
  const keysEmptyState = document.getElementById("keys-empty-state");
  const btnShowKeyForm = document.getElementById("btn-show-key-form");
  const keyCreateBox = document.getElementById("key-create-box");
  const btnCancelKeyCreate = document.getElementById("btn-cancel-key-create");
  const createKeyForm = document.getElementById("create-key-form");
  const keyNameInput = document.getElementById("key-name-input");
  const keyGeneratedAlert = document.getElementById("key-generated-alert");
  const newlyGeneratedKey = document.getElementById("newly-generated-key");
  const exampleKeySlug = document.getElementById("example-key-slug");
  const btnCopyNewKey = document.getElementById("btn-copy-new-key");
  const btnDismissKeyAlert = document.getElementById("btn-dismiss-key-alert");

  const quickstartCode = document.getElementById("quickstart-code");
  const btnCopyExample = document.getElementById("btn-copy-example");

  function getCsrfToken() {
    const meta = document.querySelector('meta[name="csrf-token"]');
    return meta ? meta.getAttribute("content") : "";
  }

  function showToast(msg, type = "info") {
    const container = document.getElementById("toast-container");
    if (!container) return;
    const toast = document.createElement("div");
    toast.className = `toast ${type}`;
    toast.innerHTML = `<i class="fa-solid ${type === "error" ? "fa-circle-exclamation" : "fa-circle-check"}"></i> <span>${msg}</span>`;
    container.appendChild(toast);
    setTimeout(() => {
      toast.style.opacity = "0";
      toast.style.transform = "translateX(20px)";
      setTimeout(() => toast.remove(), 300);
    }, 4000);
  }

  function formatDate(isoStr) {
    if (!isoStr) return "Never";
    try {
      const d = new Date(isoStr);
      return d.toLocaleDateString("en-US", {
        month: "short",
        day: "numeric",
        year: "numeric",
        hour: "2-digit",
        minute: "2-digit",
      });
    } catch {
      return isoStr;
    }
  }

  // Fetch and render keys
  async function loadKeys() {
    try {
      const res = await fetch("/api/v1/keys", {
        headers: { "Accept": "application/json" }
      });
      if (res.status === 401) {
        window.location.href = "/login";
        return;
      }
      const data = await res.json();
      if (!data.success) {
        showToast(data.error?.message || "Failed to load API keys.", "error");
        return;
      }
      renderKeys(data.keys || []);
    } catch (err) {
      console.error("Failed to fetch keys:", err);
      showToast("Network error while loading API keys.", "error");
    }
  }

  function renderKeys(keys) {
    if (!keys || keys.length === 0) {
      keysTbody.innerHTML = "";
      keysEmptyState.style.display = "block";
      return;
    }
    keysEmptyState.style.display = "none";

    keysTbody.innerHTML = keys.map(k => {
      const isActive = !k.revoked_at;
      const statusBadge = isActive
        ? `<span class="pill pill-open" style="font-size:0.75rem;"><span class="pill-dot pulse"></span>Active</span>`
        : `<span class="pill" style="font-size:0.75rem; color:var(--alert-magenta); background:rgba(255,47,126,0.12); border:1px solid rgba(255,47,126,0.3);"><span class="pill-dot" style="background:var(--alert-magenta);"></span>Revoked</span>`;

      const actionBtn = isActive
        ? `<button type="button" class="btn btn-outline btn-sm btn-revoke-key" data-id="${k.id}" data-name="${encodeURIComponent(k.name)}" style="color:var(--alert-magenta); border-color:rgba(255,47,126,0.35); padding:4px 10px; font-size:0.8rem;"><i class="fa-solid fa-ban"></i> Revoke</button>`
        : `<span style="color:var(--text-muted); font-size:0.8rem;">Revoked</span>`;

      return `
        <tr>
          <td><b style="color:var(--text-main); font-family:var(--font-ui);">${escapeHtml(k.name)}</b></td>
          <td>
            <div style="display:flex; align-items:center; gap:8px;">
              <code style="font-family:var(--font-mono); color:var(--signal-green); background:rgba(0,0,0,0.35); padding:3px 8px; border-radius:4px; font-size:0.85rem;">${escapeHtml(k.masked_key || k.key_prefix)}</code>
            </div>
          </td>
          <td style="font-size:0.85rem; color:var(--text-muted);">${formatDate(k.created_at)}</td>
          <td style="font-size:0.85rem; color:var(--text-muted);">${formatDate(k.last_used_at)}</td>
          <td>${statusBadge}</td>
          <td style="text-align:right;">${actionBtn}</td>
        </tr>
      `;
    }).join("");

    // Attach revoke listeners
    document.querySelectorAll(".btn-revoke-key").forEach(btn => {
      btn.addEventListener("click", async () => {
        const id = btn.getAttribute("data-id");
        const name = decodeURIComponent(btn.getAttribute("data-name") || "this key");
        if (!confirm(`Are you sure you want to revoke API key "${name}"? This action cannot be undone.`)) {
          return;
        }
        await revokeKey(id);
      });
    });
  }

  function escapeHtml(str) {
    if (!str) return "";
    return str.replace(/[&<>'"]/g, tag => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", "'": "&#39;", "\"": "&quot;"
    }[tag] || tag));
  }

  // Toggle creation box
  if (btnShowKeyForm) {
    btnShowKeyForm.addEventListener("click", () => {
      keyCreateBox.style.display = "block";
      keyNameInput.focus();
    });
  }
  if (btnCancelKeyCreate) {
    btnCancelKeyCreate.addEventListener("click", () => {
      keyCreateBox.style.display = "none";
      keyNameInput.value = "";
    });
  }

  // Handle key creation
  if (createKeyForm) {
    createKeyForm.addEventListener("submit", async (e) => {
      e.preventDefault();
      const name = keyNameInput.value.trim();
      if (!name) return;

      try {
        const res = await fetch("/api/v1/keys", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "X-CSRF-Token": getCsrfToken(),
            "Accept": "application/json"
          },
          body: JSON.stringify({ name })
        });
        const data = await res.json();
        if (data.success && data.key) {
          keyCreateBox.style.display = "none";
          keyNameInput.value = "";

          // Show the full key once
          newlyGeneratedKey.value = data.key.api_key;
          exampleKeySlug.textContent = data.key.api_key.substring(0, 16) + "...";
          keyGeneratedAlert.style.display = "block";
          keyGeneratedAlert.scrollIntoView({ behavior: "smooth", block: "nearest" });

          showToast("API key generated successfully!", "success");
          loadKeys();
        } else {
          showToast(data.error?.message || "Failed to generate API key.", "error");
        }
      } catch (err) {
        console.error("Key creation error:", err);
        showToast("Error communicating with server.", "error");
      }
    });
  }

  // Revoke Key
  async function revokeKey(keyId) {
    try {
      const res = await fetch(`/api/v1/keys/${keyId}`, {
        method: "DELETE",
        headers: {
          "X-CSRF-Token": getCsrfToken(),
          "Accept": "application/json"
        }
      });
      const data = await res.json();
      if (data.success) {
        showToast("API key revoked successfully.", "success");
        loadKeys();
      } else {
        showToast(data.error?.message || "Failed to revoke API key.", "error");
      }
    } catch (err) {
      console.error("Revoke error:", err);
      showToast("Error revoking key.", "error");
    }
  }

  // Copy new key button
  if (btnCopyNewKey) {
    btnCopyNewKey.addEventListener("click", () => {
      if (newlyGeneratedKey && newlyGeneratedKey.value) {
        navigator.clipboard.writeText(newlyGeneratedKey.value).then(() => {
          showToast("API key copied to clipboard!", "success");
          btnCopyNewKey.innerHTML = '<i class="fa-solid fa-check"></i> Copied!';
          setTimeout(() => {
            btnCopyNewKey.innerHTML = '<i class="fa-solid fa-copy"></i> Copy Key';
          }, 2000);
        });
      }
    });
  }

  // Dismiss key alert
  if (btnDismissKeyAlert) {
    btnDismissKeyAlert.addEventListener("click", () => {
      keyGeneratedAlert.style.display = "none";
      if (newlyGeneratedKey) newlyGeneratedKey.value = "";
    });
  }

  // Copy base URL chip
  document.querySelectorAll(".btn-copy-chip").forEach(btn => {
    btn.addEventListener("click", () => {
      const text = btn.getAttribute("data-copy") || "";
      navigator.clipboard.writeText(window.location.origin + text).then(() => {
        showToast("Copied to clipboard!", "success");
      });
    });
  });

  // Quick Start Examples Tabs
  const quickstartSnippets = {
    "tab-curl-health": `curl -X GET https://cyberport-scanner.onrender.com/api/v1/health`,
    "tab-curl-scan": `curl -X POST https://cyberport-scanner.onrender.com/api/v1/scans \\
  -H "Authorization: Bearer YOUR_API_KEY" \\
  -H "Content-Type: application/json" \\
  -d '{"target": "192.168.1.10", "start_port": 1, "end_port": 100}'`,
    "tab-curl-status": `curl -X GET https://cyberport-scanner.onrender.com/api/v1/scans/123 \\
  -H "Authorization: Bearer YOUR_API_KEY"`,
    "tab-curl-ports": `curl -X GET https://cyberport-scanner.onrender.com/api/v1/ports/443 \\
  -H "Authorization: Bearer YOUR_API_KEY"`
  };

  ["tab-curl-health", "tab-curl-scan", "tab-curl-status", "tab-curl-ports"].forEach(tabId => {
    const tabBtn = document.getElementById(tabId);
    if (tabBtn) {
      tabBtn.addEventListener("click", () => {
        document.querySelectorAll(".presets-row .preset-chip").forEach(c => c.classList.remove("active"));
        tabBtn.classList.add("active");
        if (quickstartCode) {
          quickstartCode.textContent = quickstartSnippets[tabId];
        }
      });
    }
  });

  if (btnCopyExample && quickstartCode) {
    btnCopyExample.addEventListener("click", () => {
      navigator.clipboard.writeText(quickstartCode.textContent).then(() => {
        showToast("Code copied to clipboard!", "success");
        btnCopyExample.innerHTML = '<i class="fa-solid fa-check"></i> Copied';
        setTimeout(() => {
          btnCopyExample.innerHTML = '<i class="fa-regular fa-copy"></i> Copy';
        }, 2000);
      });
    });
  }

  // Initial load
  loadKeys();
});
