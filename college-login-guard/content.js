// ============================================================
// CONTENT SCRIPT — Warning banner + Form-action monitoring
// ============================================================

chrome.runtime.onMessage.addListener((msg) => {
  if (msg.type === "SHOW_WARNING") showWarningBanner(msg);
});

// Escapes a value for safe interpolation into innerHTML. Every piece of
// dynamic text in this file (hostnames, reasons, flags, whitelist entries,
// history entries, etc.) ultimately originates from the page being visited
// or from user-editable storage, so it must never be trusted as raw HTML.
function escapeHTML(str) {
  return String(str ?? "").replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  }[c]));
}

// ============================================================
// MULTI-PART TLD SUPPORT
// ============================================================
const MULTI_PART_TLDS = [
  "co.in", "ac.in", "edu.in", "gov.in", "net.in", "org.in", "res.in",
  "co.uk", "org.uk", "ac.uk", "gov.uk", "net.uk",
  "com.au", "net.au", "org.au", "edu.au",
  "co.jp", "ac.jp", "co.nz", "co.za"
];

function getRootDomain(hostname) {
  const parts = hostname.split(".");
  if (parts.length <= 2) return hostname;
  const lastTwo = parts.slice(-2).join(".");
  const lastThree = parts.slice(-3).join(".");
  if (MULTI_PART_TLDS.includes(lastTwo)) return lastThree;
  return lastTwo;
}

// ============================================================
// FORM-ACTION EXTERNAL DOMAIN DETECTION
// ============================================================
function monitorForms() {
  const pageDomain = location.hostname;
  const pageRoot = getRootDomain(pageDomain);

  function checkForm(form) {
    const action = form.action;
    if (!action || action.startsWith("javascript:")) return;
    try {
      const actionUrl = new URL(action, location.href);
      const actionDomain = actionUrl.hostname;
      const actionRoot = getRootDomain(actionDomain);
      if (actionDomain && actionRoot !== pageRoot) {
        chrome.runtime.sendMessage({
          type: "FORM_ACTION_EXTERNAL",
          hostname: pageDomain,
          externalDomain: actionDomain,
          isHttps: location.protocol === "https:"
        });
      }
    } catch (_) {}
  }

  function scanForms() {
    document.querySelectorAll("form").forEach(checkForm);
  }

  const observer = new MutationObserver(() => scanForms());

  if (document.body) {
    scanForms();
    observer.observe(document.body, { childList: true, subtree: true });
  } else {
    document.addEventListener("DOMContentLoaded", () => {
      scanForms();
      observer.observe(document.body, { childList: true, subtree: true });
    });
  }

  document.addEventListener("submit", (e) => {
    if (e.target?.tagName === "FORM") checkForm(e.target);
  }, true);
}

monitorForms();

// ============================================================
// PASSWORD FIELD ALARM
// ============================================================
(function passwordFieldAlarm() {
  const GATE_REGEX = /(college|campus|student|lms|erp|kct|edu|portal|login|signin|auth|account|sso|verify)/i;
  if (!GATE_REGEX.test(window.location.href)) return; // Kills the observer instantly for normal sites
  let alarmShown = false;

  function playAlarmSound() {
    try {
      const ctx = new (window.AudioContext || window.webkitAudioContext)();
      [0, 0.25, 0.5].forEach(offset => {
        const osc = ctx.createOscillator();
        const gain = ctx.createGain();
        osc.connect(gain);
        gain.connect(ctx.destination);
        osc.type = "square";
        osc.frequency.setValueAtTime(880, ctx.currentTime + offset);
        gain.gain.setValueAtTime(0, ctx.currentTime + offset);
        gain.gain.linearRampToValueAtTime(0.15, ctx.currentTime + offset + 0.02);
        gain.gain.linearRampToValueAtTime(0, ctx.currentTime + offset + 0.18);
        osc.start(ctx.currentTime + offset);
        osc.stop(ctx.currentTime + offset + 0.2);
      });
    } catch (_) {}
  }

  function showPasswordAlarmToast(fieldCount, isHttps) {
    if (alarmShown) return;
    alarmShown = true;

    chrome.storage.sync.get(["passwordAlarmEnabled"], (data) => {
      if (data.passwordAlarmEnabled === false) return;

      if (!isHttps) playAlarmSound();

      const toast = document.createElement("div");
      toast.id = "clg-pw-alarm-toast";

      const isHttp = !isHttps;
      const sev = isHttp ? "clg-alarm-danger" : "clg-alarm-warn";
      const icon = isHttp ? "🔓" : "🔑";
      const title = isHttp
        ? "Password Field on Unsecured Page!"
        : "Password Field Detected";
      const msg = isHttp
        ? `${fieldCount} password field${fieldCount > 1 ? "s" : ""} found on an HTTP page — your credentials will be sent <strong>unencrypted</strong>.`
        : `${fieldCount} password field${fieldCount > 1 ? "s" : ""} found. This page is HTTPS — verify it's the official site before logging in.`;

      toast.innerHTML = `
        <div class="clg-alarm-inner ${sev}">
          <div class="clg-alarm-icon">${icon}</div>
          <div class="clg-alarm-body">
            <div class="clg-alarm-title">${title}</div>
            <div class="clg-alarm-msg">${msg}</div>
          </div>
          <button class="clg-alarm-close" title="Dismiss">✕</button>
        </div>`;

      const style = document.createElement("style");
      style.textContent = `
        #clg-pw-alarm-toast {
          position: fixed;
          bottom: 20px; right: 20px; z-index: 2147483646;
          max-width: 340px; min-width: 260px;
          font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
          animation: clg-toast-in 0.38s cubic-bezier(0.34,1.56,0.64,1) both;
        }
        @keyframes clg-toast-in {
          from { opacity:0; transform: translateY(30px) scale(0.92); }
          to   { opacity:1; transform: translateY(0) scale(1); }
        }
        .clg-alarm-inner {
          border-radius: 12px;
          padding: 12px 14px;
          display: flex; align-items: flex-start; gap: 10px;
          box-shadow: 0 8px 32px rgba(0,0,0,0.45);
        }
        .clg-alarm-danger {
          background: #1a0505;
          border: 1.5px solid #ef4444;
          animation: clg-alarm-pulse 1.6s ease-in-out 0.5s infinite;
        }
        @keyframes clg-alarm-pulse {
          0%,100%{ box-shadow: 0 8px 32px rgba(0,0,0,0.45), 0 0 0 0 rgba(239,68,68,0.4); }
          50%    { box-shadow: 0 8px 32px rgba(239,68,68,0.3), 0 0 0 6px rgba(239,68,68,0); }
        }
        .clg-alarm-warn { background: #1a1200; border: 1.5px solid #f59e0b; }
        .clg-alarm-icon { font-size: 22px; line-height: 1; padding-top: 2px; }
        .clg-alarm-body { flex: 1; }
        .clg-alarm-title {
          font-size: 13px;
          font-weight: 700;
          color: #f87171; margin-bottom: 3px;
        }
        .clg-alarm-warn .clg-alarm-title { color: #fbbf24; }
        .clg-alarm-msg { font-size: 11.5px; color: #94a3b8; line-height: 1.5; }
        .clg-alarm-msg strong { color: #f87171; }
        .clg-alarm-close {
          background: none;
          border: none; color: #64748b;
          font-size: 14px; cursor: pointer; padding: 0 2px;
          line-height: 1; flex-shrink: 0; margin-top: 2px;
        }
        .clg-alarm-close:hover { color: #cbd5e1; }
      `;
      document.head.appendChild(style);
      document.body.appendChild(toast);

      toast.querySelector(".clg-alarm-close").addEventListener("click", () => {
        toast.style.animation = "none";
        toast.style.opacity = "0";
        toast.style.transform = "translateY(20px)";
        toast.style.transition = "all 0.25s ease";
        setTimeout(() => toast.remove(), 260);
      });

      if (isHttps) setTimeout(() => toast?.remove(), 12000);
    });
  }

  function checkForPasswordFields() {
    const pwFields = document.querySelectorAll("input[type='password']");
    if (pwFields.length > 0 && !alarmShown) {
      showPasswordAlarmToast(pwFields.length, location.protocol === "https:");
      chrome.runtime.sendMessage({
        type: "PASSWORD_FIELD_DETECTED",
        hostname: location.hostname,
        fieldCount: pwFields.length,
        isHttps: location.protocol === "https:"
      });
    }
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", () => setTimeout(checkForPasswordFields, 800));
  } else {
    setTimeout(checkForPasswordFields, 800);
  }

  const pwObserver = new MutationObserver(() => {
    if (!alarmShown) checkForPasswordFields();
  });
  if (document.body) {
    pwObserver.observe(document.body, { childList: true, subtree: true });
  } else {
    document.addEventListener("DOMContentLoaded", () => {
      pwObserver.observe(document.body, { childList: true, subtree: true });
    });
  }
})();

// ============================================================
// WARNING BANNER — Animated Entry
// ============================================================
function showWarningBanner({ status, reason, flags, resolvedIPs, trustedIPs, trustedDomains, typosquatMatch, hostname, sslInfo, domainAge, redirectInfo }) {
  if (document.getElementById("clg-login-guard-banner")) return;
  const isDanger = status === "danger";

  const inject = () => {
    const banner = document.createElement("div");
    banner.id = "clg-login-guard-banner";

    const flagsHTML = (flags || []).map((f, i) =>
      `<div class="clg-flag" style="animation-delay:${0.35 + i * 0.08}s">⚠ ${escapeHTML(f)}</div>`
    ).join("");
    const typoHTML = typosquatMatch?.detected
      ? `<div class="clg-typo">🔍 This domain closely mimics <strong>${escapeHTML(typosquatMatch.matchedDomain)}</strong></div>` : "";
    let extraDetails = "";
    if (sslInfo) {
      extraDetails += `<div class="clg-row"><span class="clg-label">SSL Grade</span><span class="clg-value ${sslInfo.grade === 'A' ? 'clg-good' : sslInfo.grade === 'F' ? 'clg-bad' : ''}">${escapeHTML(sslInfo.grade || "?")} ${sslInfo.hasSSL ? "🔒" : "⚠"}</span></div>`;
    }
    if (domainAge?.checked) {
      const ageText = domainAge.ageDays != null ? `${domainAge.ageDays} days old` : "Unknown";
      extraDetails += `<div class="clg-row"><span class="clg-label">Domain Age</span><span class="clg-value ${domainAge.suspicious ? 'clg-bad' : ''}">${escapeHTML(ageText)}</span></div>`;
    }
    if (redirectInfo?.hops > 0) {
      extraDetails += `<div class="clg-row"><span class="clg-label">Redirects</span><span class="clg-value ${redirectInfo.suspicious ? 'clg-bad' : ''}">${redirectInfo.hops} hop(s)</span></div>`;
    }

    const isDomainOfficial = (trustedDomains || []).some(d => location.hostname === d || location.hostname.endsWith("." + d));
    const domainClass = isDomainOfficial ? "clg-good" : "clg-bad";

    banner.innerHTML = `
      <div id="clg-overlay">
        <div id="clg-modal" class="${status}">
          <div id="clg-icon">${isDanger ? "🚨" : "⚠️"}</div>
          <h1 id="clg-title">${isDanger ? "Fake Login Page Detected!" : "Suspicious Page Warning"}</h1>
          <p id="clg-desc">${isDanger
            ? "This page is <strong>NOT</strong> your college's official login. It may be stealing your credentials."
            : "This page has suspicious characteristics. Proceed with caution."}</p>
          ${typoHTML}
          ${flagsHTML ? `<div id="clg-flags">${flagsHTML}</div>` : ""}
          <div id="clg-detail" class="clg-detail-anim">
            <div class="clg-row"><span class="clg-label">Page Domain</span><span class="clg-value ${domainClass}">${escapeHTML(location.hostname)}</span></div>
            <div class="clg-row"><span class="clg-label">Official Domains</span><span class="clg-value clg-good">${escapeHTML((trustedDomains||[]).join(", "))}</span></div>
            <div class="clg-row"><span class="clg-label">Resolved IPs</span><span class="clg-value">${escapeHTML((resolvedIPs||[]).join(", ")) || "Unknown"}</span></div>
            ${extraDetails}
          </div>
          ${isDanger ? `<p id="clg-advice">⛔ Do NOT enter your username or password on this page.</p>` : ""}
          <div id="clg-actions">
            <button id="clg-leave">Leave This Page</button>
            <button id="clg-whitelist">Add to Safe List</button>
            <button id="clg-report">Report Site</button>
            <button id="clg-dismiss">${isDanger ? "I Understand the Risk" : "Dismiss"}</button>
          </div>
          <div id="clg-feedback" style="display:none;font-size:12px;margin-top:10px;"></div>
        </div>
      </div>`;

    const style = document.createElement("style");
    style.textContent = `
      #clg-overlay {
        position: fixed; inset: 0; z-index: 2147483647;
        background: rgba(0,0,0,0); display: flex;
        align-items: center; justify-content: center;
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
        backdrop-filter: blur(0px); animation: clg-backdrop-in 0.4s ease forwards;
      }
      @keyframes clg-backdrop-in {
        to { background: rgba(0,0,0,0.88); backdrop-filter: blur(6px); }
      }
      #clg-modal {
        background: #0f172a; color: #e2e8f0; border-radius: 18px;
        padding: 32px 38px; max-width: 520px; width: 92%; text-align: center;
        max-height: 90vh; overflow-y: auto; opacity: 0;
        transform: translateY(-28px) scale(0.95);
        animation: clg-modal-in 0.42s cubic-bezier(0.34, 1.56, 0.64, 1) 0.12s forwards;
      }
      @keyframes clg-modal-in {
        to { opacity: 1; transform: translateY(0) scale(1); }
      }
      #clg-modal.danger {
        border: 2px solid #ef4444; box-shadow: 0 0 0 0 rgba(239,68,68,0.5);
        animation: clg-modal-in 0.42s cubic-bezier(0.34,1.56,0.64,1) 0.12s forwards, clg-danger-pulse 1.8s ease-in-out 0.8s infinite;
      }
      @keyframes clg-danger-pulse {
        0%,100% { box-shadow: 0 0 40px rgba(239,68,68,0.25), 0 0 0 0 rgba(239,68,68,0.4); }
        50%      { box-shadow: 0 0 80px rgba(239,68,68,0.45), 0 0 0 8px rgba(239,68,68,0); }
      }
      #clg-modal.warning {
        border: 2px solid #f59e0b; box-shadow: 0 0 80px rgba(245,158,11,0.25);
        animation: clg-modal-in 0.42s cubic-bezier(0.34,1.56,0.64,1) 0.12s forwards;
      }
      #clg-icon {
        font-size: 50px; margin-bottom: 8px;
        animation: clg-icon-drop 0.6s cubic-bezier(0.34,1.56,0.64,1) 0.3s both;
      }
      @keyframes clg-icon-drop {
        from { opacity: 0; transform: scale(0.3) translateY(-20px); }
        to   { opacity: 1; transform: scale(1) translateY(0); }
      }
      .danger #clg-icon { animation: clg-icon-drop 0.6s cubic-bezier(0.34,1.56,0.64,1) 0.3s both, clg-shake 0.5s ease 0.95s; }
      @keyframes clg-shake {
        0%,100%{transform:translateX(0)} 20%{transform:translateX(-5px)} 40%{transform:translateX(5px)} 60%{transform:translateX(-4px)} 80%{transform:translateX(4px)}
      }
      #clg-title {
        font-size: 21px; font-weight: 800; margin: 0 0 8px;
        opacity: 0; transform: translateY(10px);
        animation: clg-fade-up 0.35s ease 0.42s forwards;
      }
      @keyframes clg-fade-up {
        to { opacity: 1; transform: translateY(0); }
      }
      .danger #clg-title { color: #f87171; }
      .warning #clg-title { color: #fbbf24; }
      #clg-desc {
        font-size: 13px; color: #94a3b8; margin: 0 0 14px; line-height: 1.6;
        opacity: 0; transform: translateY(8px);
        animation: clg-fade-up 0.35s ease 0.52s forwards;
      }
      #clg-desc strong { color: #f87171; }
      .clg-typo {
        background: #1e1040; border: 1px solid #6d28d9; border-radius: 8px;
        padding: 8px 12px; font-size: 13px; color: #c4b5fd; margin-bottom: 10px;
        opacity: 0; transform: translateX(-12px);
        animation: clg-slide-right 0.3s ease 0.58s forwards;
      }
      @keyframes clg-slide-right { to { opacity:1; transform:translateX(0); } }
      .clg-typo strong { color: #a78bfa; }
      #clg-flags { margin-bottom: 12px; }
      .clg-flag {
        background: #1c0a0a; border: 1px solid #7f1d1d; border-radius: 8px;
        padding: 7px 12px; font-size: 12px; color: #fca5a5; margin-bottom: 5px; text-align: left;
        opacity: 0; transform: translateX(-14px);
        animation: clg-slide-right 0.32s ease both;
      }
      .warning .clg-flag { background: #1c1400; border-color: #92400e; color: #fcd34d; }
      .clg-detail-anim {
        background: #1e293b; border-radius: 10px; padding: 12px 14px;
        margin-bottom: 14px; text-align: left;
        opacity: 0; transform: translateY(10px);
        animation: clg-fade-up 0.35s ease 0.68s forwards;
      }
      .clg-row { display:flex; gap:10px; align-items:flex-start; padding:5px 0; border-bottom:1px solid #334155; font-size:12px; }
      .clg-row:last-child { border-bottom: none; }
      .clg-label { color:#64748b; min-width:100px; font-size:10px; font-weight:700; text-transform:uppercase; padding-top:1px; }
      .clg-value { color:#cbd5e1; flex:1; word-break:break-all; }
      .clg-bad  { color:#f87171; font-weight:700; }
      .clg-good { color:#4ade80; font-weight:600; }
      #clg-advice {
        background: #450a0a; border: 1px solid #991b1b; border-radius: 8px;
        padding: 9px 14px; font-size: 13px; font-weight: 700; color: #fca5a5; margin-bottom: 18px;
        opacity: 0; transform: translateY(8px);
        animation: clg-fade-up 0.35s ease 0.78s forwards;
      }
      #clg-actions {
        display: flex; gap: 8px; justify-content: center; flex-wrap: wrap;
        opacity: 0; transform: translateY(10px);
        animation: clg-fade-up 0.35s ease 0.88s forwards;
      }
      #clg-leave {
        padding: 10px 20px; border: none; border-radius: 8px;
        font-size: 13px; font-weight: 700; cursor: pointer; color: white;
      }
      .danger #clg-leave  { background: #ef4444; }
      .warning #clg-leave { background: #f59e0b; }
      #clg-whitelist {
        padding: 10px 16px; background: #052e16; color: #4ade80;
        border: 1px solid #166534; border-radius: 8px; font-size: 13px; cursor: pointer;
      }
      #clg-whitelist:hover { background: #14532d; }
      #clg-report {
        padding: 10px 14px; background: #1e3a5f; color: #60a5fa;
        border: 1px solid #1e40af; border-radius: 8px; font-size: 13px; cursor: pointer;
      }
      #clg-dismiss {
        background: transparent; color: #64748b; border: 1px solid #334155;
        padding: 10px 14px; border-radius: 8px; font-size: 13px; cursor: pointer;
      }
    `;

    document.head.appendChild(style);
    document.body.prepend(banner);

    const feedback = document.getElementById("clg-feedback");

    document.getElementById("clg-leave").onclick = () => { history.back(); banner.remove(); };
    document.getElementById("clg-dismiss").onclick = () => banner.remove();

    document.getElementById("clg-whitelist").onclick = () => {
      chrome.runtime.sendMessage({ type: "ADD_TO_WHITELIST", hostname: location.hostname }, () => {
        feedback.style.display = "block";
        feedback.style.color = "#4ade80";
        feedback.textContent = `✓ "${location.hostname}" added to your safe list.`;
        document.getElementById("clg-whitelist").disabled = true;
        document.getElementById("clg-whitelist").textContent = "Added ✓";
        setTimeout(() => banner.remove(), 2000);
      });
    };

    document.getElementById("clg-report").onclick = () => {
      chrome.runtime.sendMessage({ type: "REPORT_SITE" });
      feedback.style.display = "block";
      feedback.style.color = "#60a5fa";
      feedback.textContent = "✓ Site reported and logged.";
      document.getElementById("clg-report").disabled = true;
      document.getElementById("clg-report").textContent = "Reported ✓";
    };
  };

  if (document.body) inject();
  else document.addEventListener("DOMContentLoaded", inject);
}