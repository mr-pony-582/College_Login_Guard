// ============================================================
// POPUP SCRIPT
// ============================================================

const CHECK_ORDER = [
  "chk-domain", "chk-wl", "chk-https", "chk-ip",
  "chk-typo", "chk-ssl", "chk-redirect", "chk-domainage"
];
function startCheckTimeline() {
  CHECK_ORDER.forEach((id, i) => {
    const row = document.getElementById(id)?.closest(".check-row");
    if (!row) return;
    const valEl = document.getElementById(id);
    if (valEl) { valEl.textContent = ""; valEl.className = "check-val na scanning"; }
    setTimeout(() => { row.classList.add("tl-visible"); }, 80 + i * 90);
  });
}

function revealCheck(id, pass, passLabel, failLabel) {
  const el = document.getElementById(id);
  if (!el) return;
  el.classList.remove("scanning");
  setCheck(id, pass, passLabel, failLabel);
  const row = el.closest(".check-row");
  if (row) {
    row.style.transition = "background 0.15s";
    row.style.background = pass === false ?
      "rgba(239,68,68,0.07)"
                         : pass === true  ?
      "rgba(74,222,128,0.06)"
                         : "rgba(245,158,11,0.06)";
    setTimeout(() => { row.style.background = ""; }, 600);
  }
}

// ── TABS ──────────────────────────────────────────────────
document.querySelectorAll(".tab").forEach(tab => {
  tab.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach(t => t.classList.remove("active"));
    document.querySelectorAll(".tab-content").forEach(t => t.classList.remove("active"));
    tab.classList.add("active");
    document.getElementById("tab-" + tab.dataset.tab).classList.add("active");
    if (tab.dataset.tab === "history") loadHistory();
    if (tab.dataset.tab === "settings") loadSettings();
    if (tab.dataset.tab === "whitelist") loadWhitelist();
  });
});

// Escapes a value for safe interpolation into innerHTML. Hostnames, reasons,
// whitelist entries, and history come from the visited page or from
// user-editable / imported storage, so they must never be trusted as raw HTML.
function escapeHTML(str) {
  return String(str ?? "").replace(/[&<>"']/g, (c) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
  }[c]));
}

// ── STATUS CONFIG ──────────────────────────────────────────
const statusConfig = {
  safe:     { emoji: "✅", label: "Page Looks Safe" },
  warning:  { emoji: "⚠️", label: "Suspicious Page" },
  danger:   { emoji: "🚨", label: "Fake Page Detected!" },
  checking: { emoji: "⏳", label: "Checking..." },
  unknown:  { emoji: "❓", label: "Not Analyzed" }
};

function setCheck(id, pass, passLabel, failLabel) {
  const el = document.getElementById(id);
  if (!el) return;
  if (pass === null || pass === undefined) { el.textContent = "N/A"; el.className = "check-val na"; return; }
  if (pass === "warn") { el.textContent = failLabel || "⚠ Warn"; el.className = "check-val warn"; return; }
  el.textContent = pass ? (passLabel || "Pass ✓") : (failLabel || "Fail ✗");
  el.className = "check-val " + (pass ? "pass" : "fail");
}

function setPill(id, state, label) {
  const el = document.getElementById(id);
  if (!el) return;
  el.className = `feat-pill ${state}`;
  if (label) el.textContent = label;
}

// ── RISK SCORE METER ─────────────────────────────────
function renderRiskScore(score) {
  const wrap = document.getElementById("risk-meter-wrap");
  const numEl = document.getElementById("risk-score-num");
  const barEl = document.getElementById("risk-bar-fill");
  wrap.style.display = "block";

  const tier = score <= 25 ? "low" : score <= 60 ? "medium" : "high";
  numEl.textContent = score;
  numEl.className = `risk-score-num ${tier}`;
  barEl.style.width = `${score}%`;
  barEl.className = `risk-bar-fill ${tier}`;
}

// ── CURRENT TAB STATE ──────────────────────────────────────
let _currentStatus = null;
let _currentTabId = null;
let _currentHostname = null;

// Listen for background status updates and auto-refresh the popup UI
chrome.runtime.onMessage.addListener((msg) => {
  if (msg.type === "STATUS_UPDATED" && msg.tabId === _currentTabId) {
    window.location.reload();
  }
});

(function initStatus() {
  const box = document.getElementById("status-box");
  box.className = "status-box checking";
  document.getElementById("status-emoji").textContent = "⏳";
  document.getElementById("status-label").textContent = "Loading...";
  document.getElementById("status-reason").textContent = "Fetching page analysis...";
  startCheckTimeline();

  chrome.tabs.query({ active: true, currentWindow: true }, ([tab]) => {
    if (!tab) {
      document.getElementById("status-label").textContent = "No active tab";
      document.getElementById("status-reason").textContent = "Could not detect the current tab.";
      return;
    }
    _currentTabId = tab.id;

    chrome.runtime.sendMessage({ type: "GET_STATUS", tabId: tab.id }, (s) => {
      s = s || { status: "unknown" };
      _currentStatus = s;
      _currentHostname = s.hostname;

      // ── STATUS BOX ──
      const cfg = statusConfig[s.status] || statusConfig.unknown;
      document.getElementById("status-box").className = `status-box ${s.status}`;
      document.getElementById("status-emoji").textContent = cfg.emoji;
      document.getElementById("status-label").textContent = cfg.label;
      document.getElementById("status-reason").textContent = s.reason || "—";
      
      if (s.sensitivityAdjusted && s.originalStatus && s.originalStatus !== s.status) {
        const adjNote = document.createElement("div");
        adjNote.style.cssText = "margin-top:5px;font-size:10px;color:#818cf8;display:flex;align-items:center;gap:4px";
        const arrow = s.status === "danger" ? "↑" : "↓";
        adjNote.textContent = `${arrow} Sensitivity adjusted: ${s.originalStatus} → ${s.status}`;
        document.getElementById("status-reason").after(adjNote);
      }

      document.getElementById("d-hostname").textContent = s.hostname || "—";
      
      // ── IPs ──
      if (s.resolvedIPs?.length) {
        const el = document.getElementById("d-ips");
        el.textContent = s.resolvedIPs.join(", ");
        el.className = "dv " + (s.ipMatchesTrusted ? "good" : "bad");
      }

      // ── RISK SCORE ──
      if (s.status !== "checking" && s.status !== "unknown") {
        chrome.runtime.sendMessage({ type: "GET_RISK_SCORE", tabId: tab.id }, (r) => {
          renderRiskScore(r?.score ?? 0);
        });
      }

      // ── OVERRIDE PANEL ──
      if (s.status !== "checking" && s.status !== "unknown") {
        document.getElementById("override-section").style.display = "block";
        if (s.hostname) loadOverrideState(s.hostname, s);
      }

      // ── CORE CHECKS ──
      if (typeof s.isOfficialDomain !== "undefined") revealCheck("chk-domain", s.isOfficialDomain, "Official ✓", "Not Official ✗");
      // On official domains, Safe List is irrelevant — show neutral instead of alarming red "Not Listed"
      if (typeof s.isWhitelisted !== "undefined") {
        if (s.isOfficialDomain) {
          // Override: show muted "Official — N/A" so it never looks like a warning
          const wlEl = document.getElementById("chk-wl");
          if (wlEl) { wlEl.textContent = "Official — N/A"; wlEl.className = "check-val na"; }
        } else {
          revealCheck("chk-wl", s.isWhitelisted, "Whitelisted ✓", "Not Listed");
        }
      }
      if (typeof s.isHttps !== "undefined") revealCheck("chk-https", s.isHttps, "Secure ✓", "No SSL ✗");
      if (typeof s.ipMatchesTrusted !== "undefined") revealCheck("chk-ip", s.ipMatchesTrusted, "Match ✓", "No Match ✗");

      if (s.typosquatMatch) {
        const el = document.getElementById("chk-typo");
        if (el) { el.classList.remove("scanning"); }
        const el2 = document.getElementById("chk-typo");
        el2.textContent = s.typosquatMatch.detected ? "Detected ✗" : "Clean ✓";
        el2.className = "check-val " + (s.typosquatMatch.detected ? "fail" : "pass");
        const row = el2.closest(".check-row");
        if (row) {
          row.style.background = s.typosquatMatch.detected ? "rgba(239,68,68,0.07)" : "rgba(74,222,128,0.06)";
          setTimeout(() => { row.style.background = ""; }, 600);
        }
      }

      // ── FEATURE PILLS ──
      document.getElementById("feat-pills").style.display = "flex";

      chrome.storage.sync.get(["sensitivityLevel"], (sd) => {
        const lvl = sd.sensitivityLevel || 3;
        const info = SENSITIVITY_INFO[lvl] || SENSITIVITY_INFO[3];
        const pillEl = document.getElementById("pill-sensitivity");
        if (pillEl) {
          pillEl.textContent = `🎚 ${info.label}`;
          const pillState = ["", "ok", "ok", "warn", "warn", "bad"][lvl] || "na";
          pillEl.className = `feat-pill ${pillState}`;
          pillEl.title = `Sensitivity L${lvl}: ${info.desc}`;
        }
      });

      // SSL
      if (s.sslInfo) {
        const ssl = s.sslInfo;
        const grade = ssl.grade || "?";
        const sslPass = !ssl.suspicious && ssl.hasSSL;
        revealCheck("chk-ssl", sslPass ? true : ssl.suspicious ? false : null, `Grade ${grade} ✓`, `Grade ${grade} ✗`);
        document.getElementById("d-ssl-grade").textContent = `Grade ${grade}`;
        document.getElementById("d-ssl-grade").className = `dv ${sslPass ? "good" : ssl.suspicious ? "bad" : ""}`;
        setPill("pill-ssl", sslPass ? "ok" : ssl.suspicious ? "bad" : "warn", `🔒 SSL ${grade}`);
      } else if (typeof s.isHttps !== "undefined") {
        revealCheck("chk-ssl", s.isHttps, "HTTPS ✓", "No HTTPS ✗");
        setPill("pill-ssl", s.isHttps ? "ok" : "bad", s.isHttps ? "🔒 SSL OK" : "🔒 No SSL");
      }

      // Redirects
      if (s.redirectInfo) {
        const ri = s.redirectInfo;
        const hops = ri.hops || 0;
        const redirectPass = !ri.suspicious;
        const redirectLabel = hops === 0 ? "Direct ✓" : `${hops} hop(s) ${ri.suspicious ? "✗" : "✓"}`;
        const el = document.getElementById("chk-redirect");
        el.classList.remove("scanning");
        el.textContent = redirectLabel;
        el.className = "check-val " + (redirectPass ? "pass" : "fail");
        document.getElementById("d-redirects").textContent = hops === 0 ? "None" : `${hops} hop(s) via ${(ri.domainsInvolved||[]).length} domain(s)`;
        document.getElementById("d-redirects").className = `dv ${ri.suspicious ? "bad" : ""}`;
        setPill("pill-redirect", redirectPass ? "ok" : "bad", hops === 0 ? "↩ Direct" : `↩ ${hops} hops`);
        const row = el.closest(".check-row");
        if (row) { row.style.background = redirectPass ? "rgba(74,222,128,0.06)" : "rgba(239,68,68,0.07)"; setTimeout(() => { row.style.background = ""; }, 600); }
      } else {
        const el = document.getElementById("chk-redirect");
        el.classList.remove("scanning");
        el.textContent = "Direct ✓"; el.className = "check-val pass";
        setPill("pill-redirect", "ok", "↩ Direct");
      }

      // Domain Age
      if (s.domainAge) {
        const da = s.domainAge;
        const el = document.getElementById("chk-domainage"); const ageEl = document.getElementById("d-domainage");
        el.classList.remove("scanning");
        if (!da.checked) { el.textContent = "Unknown"; el.className = "check-val na"; ageEl.textContent = "Could not determine"; setPill("pill-domainage", "na", "📅 Unknown"); }
        else if (da.suspicious) {
          const label = da.ageDays != null ? `${da.ageDays}d old ✗` : "New Domain ✗";
          el.textContent = label; el.className = "check-val fail";
          ageEl.textContent = da.ageDays != null ? `${da.ageDays} days (${da.createdDate?.slice(0,10) || "?"})` : "Unknown";
          ageEl.className = "dv bad"; setPill("pill-domainage", "bad", `📅 ${da.ageDays}d old`);
        } else {
          const months = da.ageMonths || Math.floor((da.ageDays||0)/30);
          const label = months >= 12 ? `${Math.floor(months/12)}yr+ ✓` : `${months}mo ✓`;
          el.textContent = label; el.className = "check-val pass";
          ageEl.textContent = da.ageDays != null ? `${da.ageDays} days` : "Established";
          ageEl.className = "dv good"; setPill("pill-domainage", "ok", `📅 ${label}`);
        }
      } else {
        document.getElementById("chk-domainage").textContent = "N/A";
        document.getElementById("chk-domainage").className = "check-val na";
        setPill("pill-domainage", "na", "📅 N/A");
      }

      // Trusted chips
      chrome.storage.sync.get(["trustedDomains", "trustedIPs"], (data) => {
        const domains = data.trustedDomains || ["admissions.kclas.ac.in", "admissions.kumaraguru.edu.in", "admissions.kumaraguru.edu.in", "blog.kct.ac.in", "campus.kumaraguru.in", "capstone.kct.ac.in", "careers.kumaraguru.edu.in", "cibi.in", "cibi.kct.ac.in", "erp.kct.ac.in", "garage.kct.ac.in", "kash.kct.ac.in", "kclas.ac.in", "kct.ac.in", "kctalumni.com", "kctbs.ac.in", "kia.ac.in", "kumaraguru.edu.in", "live.kct.ac.in", "mail.kct.ac.in", "portal.kct.ac.in", "reach.kct.ac.in", "smartapps.kct.ac.in", "www.kct.ac.in"];
        const ips = data.trustedIPs || ["172.67.187.85", "104.21.56.170", "172.67.195.208", "104.21.65.248"];
        document.getElementById("popup-domains").innerHTML = domains.map(d => `<span class="chip blue">${escapeHTML(d)}</span>`).join("");
        document.getElementById("popup-ips").innerHTML = ips.map(ip => `<span class="chip green">${escapeHTML(ip)}</span>`).join("");
      });
    });
  });
})();

// ============================================================
// VERDICT OVERRIDE
// ============================================================
function loadOverrideState(hostname, currentStatus) {
  chrome.runtime.sendMessage({ type: "GET_VERDICT_OVERRIDE", hostname }, (override) => {
    const badge = document.getElementById("override-badge");
    const current = document.getElementById("override-current");
    const select = document.getElementById("override-select");
    const reasonEl = document.getElementById("override-reason");

    if (override) {
      badge.style.display = "inline-block";
      badge.textContent = `Overridden → ${override.verdict.toUpperCase()}`;
      current.textContent = `Current override: ${override.verdict.toUpperCase()} — "${override.reason || "No reason given"}" (set ${new Date(override.timestamp).toLocaleDateString()})`;
      select.value = override.verdict;
      reasonEl.value = override.reason || "";
    } else {
      badge.style.display = "none";
      current.textContent = `Auto-verdict: ${(currentStatus?.status || "unknown").toUpperCase()}. Override below if you know better.`;
    }
  });
}

document.getElementById("override-save").addEventListener("click", () => {
  if (!_currentHostname) return;
  const verdict = document.getElementById("override-select").value;
  const reason = document.getElementById("override-reason").value.trim();
  if (!verdict) {
    document.getElementById("override-msg").textContent = "⚠ Please select a verdict.";
    document.getElementById("override-msg").style.color = "#f87171";
    document.getElementById("override-msg").style.display = "block";
    setTimeout(() => { document.getElementById("override-msg").style.display = "none"; }, 2000);
    return;
  }
  chrome.runtime.sendMessage({
    type: "SAVE_VERDICT_OVERRIDE",
    hostname: _currentHostname,
    override: { verdict, reason }
  }, () => {
    const msg = document.getElementById("override-msg");
    msg.textContent = `✓ Override saved: ${verdict.toUpperCase()}`;
    msg.style.color = "#4ade80";
    msg.style.display = "block";
    document.getElementById("override-badge").style.display = "inline-block";
    document.getElementById("override-badge").textContent = `Overridden → ${verdict.toUpperCase()}`;
    setTimeout(() => { msg.style.display = "none"; }, 2500);
  });
});

document.getElementById("override-clear").addEventListener("click", () => {
  if (!_currentHostname) return;
  chrome.runtime.sendMessage({ type: "CLEAR_VERDICT_OVERRIDE", hostname: _currentHostname }, () => {
    document.getElementById("override-select").value = "";
    document.getElementById("override-reason").value = "";
    document.getElementById("override-badge").style.display = "none";
    document.getElementById("override-current").textContent = "Override cleared. Auto-verdict is now active.";
    const msg = document.getElementById("override-msg");
    msg.textContent = "✓ Override cleared.";
    msg.style.color = "#94a3b8";
    msg.style.display = "block";
    setTimeout(() => { msg.style.display = "none"; }, 2000);
  });
});

// ============================================================
// AUTO-REPORT SUMMARY
// ============================================================
function buildReport(flaggedSites, verdictOverrides) {
  const now = new Date().toLocaleString();
  const total = flaggedSites.length;
  const dangers = flaggedSites.filter(s => s.status === "danger").length;
  const warnings = flaggedSites.filter(s => s.status === "warning").length;
  const overrideCount = Object.keys(verdictOverrides).length;

  let report = `╔══════════════════════════════════════════╗
║     COLLEGE LOGIN GUARD — THREAT REPORT   ║
╚══════════════════════════════════════════╝
Generated: ${now}
Extension: College Login Guard v1.1

━━━━━━━━━━ SUMMARY ━━━━━━━━━━
Total Flagged Sites : ${total}
  🚨 Danger         : ${dangers}
  ⚠️  Warning        : ${warnings}
Verdict Overrides   : ${overrideCount}

`;
  if (total === 0) {
    report += "No flagged sites in history.\n";
  } else {
    report += "━━━━━━━━━━ FLAGGED SITES ━━━━━━━━━━\n\n";
    flaggedSites.forEach((site, i) => {
      const override = verdictOverrides[site.hostname];
      report += `[${i+1}] ${site.hostname}
    Status   : ${site.status.toUpperCase()}${override ? ` → OVERRIDDEN to ${override.verdict.toUpperCase()}` : ""}
    Time     : ${new Date(site.timestamp).toLocaleString()}
    Reason   : ${site.reason || "—"}`;
      if (site.flags?.length) {
        report += `\n    Flags    :\n      • ${site.flags.join("\n      • ")}`;
      }
      if (override?.reason) {
        report += `\n    Override : "${override.reason}"`;
      }
      report += "\n\n";
    });
  }

  if (overrideCount > 0) {
    report += "━━━━━━━━━━ VERDICT OVERRIDES ━━━━━━━━━━\n\n";
    Object.entries(verdictOverrides).forEach(([hostname, ov]) => {
      report += `• ${hostname}: overridden to ${ov.verdict.toUpperCase()}`;
      if (ov.reason) report += ` — "${ov.reason}"`;
      report += "\n";
    });
    report += "\n";
  }

  report += `━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Report generated by College Login Guard v1.1
Stay safe online. Always verify before logging in.`;
  return report;
}

document.getElementById("btn-export").addEventListener("click", () => {
  chrome.runtime.sendMessage({ type: "EXPORT_REPORT" }, ({ flaggedSites, verdictOverrides }) => {
    const report = buildReport(flaggedSites || [], verdictOverrides || {});
    document.getElementById("report-content").textContent = report;
    document.getElementById("report-modal").classList.add("visible");
  });
});

document.getElementById("report-close").addEventListener("click", () => {
  document.getElementById("report-modal").classList.remove("visible");
});

document.getElementById("report-copy").addEventListener("click", () => {
  const text = document.getElementById("report-content").textContent;
  navigator.clipboard.writeText(text).then(() => {
    const btn = document.getElementById("report-copy");
    btn.textContent = "✓ Copied!";
    setTimeout(() => { btn.textContent = "📋 Copy Report"; }, 2000);
  });
});

// ============================================================
// WHITELIST TAB
// ============================================================
function loadWhitelist() {
  chrome.runtime.sendMessage({ type: "GET_USER_WHITELIST" }, (userList) => {
    const container = document.getElementById("user-wl-list");
    if (!userList || userList.length === 0) {
      container.innerHTML = `<div class="no-wl">No custom entries yet.<br>Add sites below or via the warning banner.</div>`;
    } else {
      container.innerHTML = userList.map(d => `
        <div class="wl-item">
          <span class="wl-domain">${escapeHTML(d)}</span>
          <span class="wl-tag user">user</span>
          <button class="wl-remove" data-domain="${escapeHTML(d)}" title="Remove">✕</button>
        </div>`).join("");
      container.querySelectorAll(".wl-remove").forEach(btn => {
        btn.addEventListener("click", () => {
          chrome.runtime.sendMessage({ type: "REMOVE_FROM_WHITELIST", hostname: btn.dataset.domain }, () => loadWhitelist());
        });
      });
    }
  });

  const GLOBAL = [
    "microsoft.com","microsoftonline.com","live.com","outlook.com","office.com","office365.com","sharepoint.com",
    "google.com","gmail.com","youtube.com","googlemail.com","apple.com","icloud.com",
    "amazon.com","aws.amazon.com","facebook.com","instagram.com","twitter.com","x.com",
    "linkedin.com","reddit.com","pinterest.com","github.com","gitlab.com","stackoverflow.com",
    "yahoo.com","paypal.com","netflix.com","spotify.com","dropbox.com","zoom.us","slack.com","notion.so","figma.com"
  ];
  document.getElementById("global-wl-list").innerHTML = GLOBAL.map(d =>
    `<div class="wl-item"><span class="wl-domain">${d}</span><span class="wl-tag global">global</span></div>`
  ).join("");
}

document.getElementById("wl-add-btn").addEventListener("click", () => {
  const input = document.getElementById("wl-input");
  const domain = input.value.trim().toLowerCase().replace(/^https?:\/\//, "").split("/")[0];
  if (!domain) return;
  chrome.runtime.sendMessage({ type: "ADD_TO_WHITELIST", hostname: domain }, () => {
    input.value = "";
    loadWhitelist();
  });
});

// ============================================================
// HISTORY TAB
// ============================================================
function loadHistory() {
  chrome.runtime.sendMessage({ type: "GET_HISTORY" }, (sites) => {
    const list = document.getElementById("history-list");
    if (!sites || sites.length === 0) {
      list.innerHTML = `<div class="no-history">No flagged sites yet.</div>`; return;
    }
    list.innerHTML = sites.map(s => `
      <div class="history-item ${s.status}">
        <div class="hi-top"><div class="hi-host">${escapeHTML(s.hostname)}</div><span class="hi-badge ${s.status}">${escapeHTML((s.status||"").toUpperCase())}</span></div>
        <div class="hi-reason">${escapeHTML(s.reason) || "—"}</div>
        <div class="hi-time">${new Date(s.timestamp).toLocaleString()}</div>
      </div>`).join("");
  });
}

document.getElementById("clear-history").addEventListener("click", () => {
  chrome.runtime.sendMessage({ type: "CLEAR_HISTORY" }, () => loadHistory());
});

// ============================================================
// SENSITIVITY SLIDER LOGIC
// ============================================================
const SENSITIVITY_INFO = {
  1: { label: 'Lenient',   cls: 'sens-1', desc: 'Only the highest confidence signals trigger danger. Very few alerts — best if you get too many false positives.' },
  2: { label: 'Light',     cls: 'sens-2', desc: 'Flags typosquatting and high-confidence signals. Minor HTTP or SSL issues show as warnings only.' },
  3: { label: 'Balanced',  cls: 'sens-3', desc: 'Flags clear threats like typosquatting and new domains as danger. Recommended for most users.' },
  4: { label: 'Sensitive', cls: 'sens-4', desc: 'Escalates quickly. SSL issues, IP mismatches, and redirect chains may trigger danger alerts.' },
  5: { label: 'Strict',    cls: 'sens-5', desc: 'Any suspicious signal can trigger danger. Expect more alerts — ideal if security is your top priority.' },
};

function updateSensitivityUI(level) {
  const info = SENSITIVITY_INFO[level] || SENSITIVITY_INFO[3];
  const badge = document.getElementById('sens-badge');
  const descEl = document.getElementById('sensitivity-desc');
  if (badge) { badge.textContent = info.label; badge.className = `sens-badge ${info.cls}`; }
  if (descEl) descEl.textContent = info.desc;
}

const sensitivitySlider = document.getElementById('set-sensitivity');
if (sensitivitySlider) {
  sensitivitySlider.addEventListener('input', (e) => updateSensitivityUI(parseInt(e.target.value)));
}

// ============================================================
// SETTINGS TAB
// ============================================================
function loadSettings() {
  chrome.storage.sync.get(["trustedDomains", "trustedIPs", "passwordAlarmEnabled", "sensitivityLevel"], (data) => {
    document.getElementById("set-domains").value = (data.trustedDomains || ["admissions.kclas.ac.in", "blog.kct.ac.in", "campus.kumaraguru.in", "capstone.kct.ac.in", "careers.kumaraguru.edu.in", "cibi.in", "cibi.kct.ac.in", "erp.kct.ac.in", "garage.kct.ac.in", "kash.kct.ac.in", "kclas.ac.in", "kct.ac.in", "kctalumni.com", "kctbs.ac.in", "kia.ac.in", "kumaraguru.edu.in", "live.kct.ac.in", "mail.kct.ac.in", "portal.kct.ac.in", "reach.kct.ac.in", "smartapps.kct.ac.in", "www.kct.ac.in"]).join("\n");
    document.getElementById("set-ips").value = (data.trustedIPs || ["172.67.187.85", "104.21.56.170", "172.67.195.208", "104.21.65.248", "13.207.240.144", "13.235.253.112", "35.154.5.103"]).join("\n");
    
    document.getElementById("set-pw-alarm").checked = data.passwordAlarmEnabled !== false;
    
    const sensitivity = data.sensitivityLevel || 3;
    const slider = document.getElementById("set-sensitivity");
    if (slider) { slider.value = sensitivity; updateSensitivityUI(sensitivity); }
  });
}

document.getElementById("save-settings").addEventListener("click", async () => {
  const saveBtn = document.getElementById("save-settings");
  const msg = document.getElementById("saved-msg");

  const domains = document.getElementById("set-domains").value.split("\n").map(s => s.trim().toLowerCase()).filter(Boolean);
  const manualIPs = document.getElementById("set-ips").value.split("\n").map(s => s.trim()).filter(Boolean);
  const passwordAlarmEnabled = document.getElementById("set-pw-alarm").checked;
  const sensitivityLevel = parseInt(document.getElementById("set-sensitivity")?.value || "3");

  saveBtn.textContent = "Resolving IPs...";
  saveBtn.disabled = true;

  const autoIPs = new Set(manualIPs);
  for (const domain of domains) {
    try {
      const htRes = await fetch(`https://api.hackertarget.com/dnslookup/?q=${encodeURIComponent(domain)}`);
      const htText = await htRes.text();
      if (!htText.startsWith("error") && !htText.includes("API count exceeded")) {
        for (const line of htText.split("\n")) {
          const m = line.match(/\bA\s+([\d.]+)/);
          if (m) autoIPs.add(m[1]);
        }
      }
    } catch (e) {}
    try {
      const cfRes = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=A`, { headers: { Accept: "application/dns-json" } });
      const cfData = await cfRes.json();
      if (cfData.Answer) cfData.Answer.filter(r => r.type === 1).forEach(r => autoIPs.add(r.data));
    } catch (e) {}
  }

  const allIPs = [...autoIPs];
  document.getElementById("set-ips").value = allIPs.join("\n");
  const toSave = { trustedDomains: domains, trustedIPs: allIPs, passwordAlarmEnabled, sensitivityLevel };

  chrome.storage.sync.set(toSave, () => {
    saveBtn.textContent = "Save Settings";
    saveBtn.disabled = false;
    msg.textContent = `✓ Saved! ${allIPs.length} IPs stored.`;
    msg.style.display = "block";
    setTimeout(() => { msg.style.display = "none"; }, 4000);
  });
});

// ============================================================
// EXPORT / IMPORT CONFIG
// ============================================================

document.getElementById("btn-export-config").addEventListener("click", () => {
  const btn = document.getElementById("btn-export-config");
  const msg = document.getElementById("config-io-msg");
  btn.disabled = true;
  btn.textContent = "Exporting…";

  chrome.runtime.sendMessage({ type: "EXPORT_CONFIG" }, (res) => {
    btn.disabled = false;
    btn.textContent = "⬇ Export Config";
    if (!res?.ok) {
      msg.textContent = "⚠ Export failed.";
      msg.style.color = "#f87171";
      msg.style.display = "block";
      setTimeout(() => { msg.style.display = "none"; }, 3000);
      return;
    }

    const blob = new Blob([JSON.stringify(res.data, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    const ts = new Date().toISOString().slice(0, 10);
    a.href = url;
    a.download = `college-login-guard-config-${ts}.json`;
    a.click();
    URL.revokeObjectURL(url);

    msg.textContent = "✓ Config exported successfully.";
    msg.style.color = "#4ade80";
    msg.style.display = "block";
    setTimeout(() => { msg.style.display = "none"; }, 3500);
  });
});

document.getElementById("btn-import-config").addEventListener("click", () => {
  document.getElementById("import-file-input").click();
});

document.getElementById("import-file-input").addEventListener("change", (e) => {
  const file = e.target.files?.[0];
  if (!file) return;

  const msg = document.getElementById("config-io-msg");
  const btn = document.getElementById("btn-import-config");
  btn.disabled = true;
  btn.textContent = "Importing…";

  const reader = new FileReader();
  reader.onload = (ev) => {
    try {
      const config = JSON.parse(ev.target.result);

      if (config._meta?.extension && config._meta.extension !== "College Login Guard") {
        throw new Error("This config file is not from College Login Guard.");
      }
      if (!config.sync) {
        throw new Error("Config file is missing settings data.");
      }

      const confirmBox = document.createElement("div");
      confirmBox.style.cssText = "position:fixed;inset:0;background:rgba(0,0,0,0.7);z-index:999;display:flex;align-items:center;justify-content:center;font-family:-apple-system,sans-serif";
      confirmBox.innerHTML = `
        <div style="background:#0f172a;border:1.5px solid #3b82f6;border-radius:14px;padding:22px 24px;max-width:300px;color:#e2e8f0;text-align:center">
          <div style="font-size:28px;margin-bottom:8px">📦</div>
          <div style="font-weight:700;font-size:14px;margin-bottom:6px">Import Config?</div>
          <div style="font-size:12px;color:#94a3b8;margin-bottom:16px">
            This will <strong style="color:#f87171">overwrite</strong> your current settings, whitelist, and history with data exported on <strong>${escapeHTML(config._meta?.exportedAt?.slice(0,10)) || "unknown date"}</strong>.
          </div>
          <div style="display:flex;gap:8px;justify-content:center">
            <button id="cfg-confirm-yes" style="padding:8px 18px;background:#3b82f6;color:#fff;border:none;border-radius:8px;font-size:13px;cursor:pointer;font-weight:700">Yes, Import</button>
            <button id="cfg-confirm-no" style="padding:8px 16px;background:transparent;color:#64748b;border:1px solid #334155;border-radius:8px;font-size:13px;cursor:pointer">Cancel</button>
          </div>
        </div>`;
      document.body.appendChild(confirmBox);

      document.getElementById("cfg-confirm-no").onclick = () => {
        confirmBox.remove();
        btn.disabled = false;
        btn.textContent = "⬆ Import Config";
        e.target.value = "";
      };

      document.getElementById("cfg-confirm-yes").onclick = () => {
        confirmBox.remove();
        chrome.runtime.sendMessage({ type: "IMPORT_CONFIG", config }, (res) => {
          btn.disabled = false;
          btn.textContent = "⬆ Import Config";
          e.target.value = "";
          if (res?.ok) {
            msg.textContent = "✓ Config imported! Reload the extension to apply.";
            msg.style.color = "#4ade80";
          } else {
            msg.textContent = `⚠ Import failed: ${res?.error || "Unknown error"}`;
            msg.style.color = "#f87171";
          }
          msg.style.display = "block";
          setTimeout(() => { msg.style.display = "none"; }, 5000);
          if (res?.ok) setTimeout(() => loadSettings(), 500);
        });
      };
    } catch (err) {
      btn.disabled = false;
      btn.textContent = "⬆ Import Config";
      e.target.value = "";
      msg.textContent = `⚠ Invalid file: ${err.message}`;
      msg.style.color = "#f87171";
      msg.style.display = "block";
      setTimeout(() => { msg.style.display = "none"; }, 4000);
    }
  };
  reader.readAsText(file);
});