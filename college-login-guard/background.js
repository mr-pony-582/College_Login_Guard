// ============================================================
// FEATURE: FIRST-RUN ONBOARDING
// ============================================================
chrome.runtime.onInstalled.addListener((details) => {
  if (details.reason === "install") {
    chrome.tabs.create({ url: chrome.runtime.getURL("onboarding.html") });
  }
});

// ============================================================
// DEFAULT CONFIGURATION
// ============================================================
const DEFAULT_CONFIG = {
  TRUSTED_DOMAINS: [
    "admissions.kclas.ac.in",
    "admissions.kumaraguru.edu.in",
    "campus.kumaraguru.in",
    "capstone.kct.ac.in",
    "careers.kumaraguru.edu.in",
    "cibi.in",
    "cibi.kct.ac.in",
    "erp.kct.ac.in",
    "garage.kct.ac.in",
    "kash.kct.ac.in",
    "kclas.ac.in",
    "kct.ac.in",
    "blog.kct.ac.in",
    "kctalumni.com",
    "kctbs.ac.in",
    "kia.ac.in",
    "kumaraguru.edu.in",
    "live.kct.ac.in",
    "mail.kct.ac.in",
    "portal.kct.ac.in",
    "reach.kct.ac.in",
    "smartapps.kct.ac.in",
    "www.kct.ac.in"
  ],
  TRUSTED_IPS: ["172.67.187.85", "104.21.56.170", "172.67.195.208", "104.21.65.248",
                "13.207.240.144", "13.235.253.112", "35.154.5.103"],
  PHISHING_KEYWORDS: [
    // College anchors
    "college", "campus", "student", "lms", "erp", "kct", "edu", "portal", "univ", "ac.in",
    // Login anchors
    "login", "signin", "auth", "verify", "account", "sso", "credential", "password"
  ],
  GLOBAL_WHITELIST: [
    "microsoft.com", "microsoftonline.com", "live.com", "outlook.com", "office.com", "office365.com", "sharepoint.com", "teams.microsoft.com",
    "google.com", "gmail.com", "accounts.google.com", "youtube.com", "googlemail.com",
    "apple.com", "icloud.com",
    "amazon.com", "aws.amazon.com", "signin.aws.amazon.com",
    "facebook.com", "instagram.com", "twitter.com", "x.com", "linkedin.com", "reddit.com", "pinterest.com",
    "github.com", "gitlab.com", "stackoverflow.com", "npmjs.com",
    "yahoo.com", "paypal.com", "netflix.com", "spotify.com", "dropbox.com", "zoom.us", "slack.com", "notion.so", "figma.com", "geeksforgeeks.org"
  ],
  SENSITIVITY_LEVEL: 3
};
const TRUSTED_FORM_DOMAINS = [
  // Google services
  "google.com",          // Covers feedburner.google.com, accounts.google.com, etc.
  "feedburner.com",      // Legacy FeedBurner (old embed URLs)
  "docs.google.com",     // Google Forms
  // Microsoft
  "microsoft.com",
  "microsoftonline.com", // Office 365 / SSO
  "live.com",
  // HubSpot / marketing
  "forms.hsforms.com",
  "hubspot.com",
  // Other safe providers
  "tally.so",
  "typeform.com",
  "formspree.io",
  "netlify.com",
  "cloudflare.com",
  "recaptcha.net",
  "gstatic.com",        // Google reCAPTCHA assets
];

let CONFIG = { ...DEFAULT_CONFIG };

async function loadConfig() {
  return new Promise(resolve => {
    chrome.storage.sync.get(["trustedDomains", "trustedIPs", "userWhitelist", "sensitivityLevel"], (data) => {
      if (data.trustedDomains) CONFIG.TRUSTED_DOMAINS = data.trustedDomains;
      if (data.trustedIPs) CONFIG.TRUSTED_IPS = data.trustedIPs;
      if (data.sensitivityLevel !== undefined) CONFIG.SENSITIVITY_LEVEL = parseInt(data.sensitivityLevel) || 3;
      CONFIG.WHITELIST = [...DEFAULT_CONFIG.GLOBAL_WHITELIST, ...(data.userWhitelist || [])];
      resolve();
    });
  });
}
loadConfig();
chrome.storage.onChanged.addListener(() => loadConfig());

// ============================================================
// TAB STATUS
// ============================================================
const tabStatus = {};

async function setTabStatus(tabId, data) {
  tabStatus[tabId] = data;
  try { await chrome.storage.session.set({ [`tab_${tabId}`]: data }); } catch (_) {}
}
async function getTabStatus(tabId) {
  if (tabStatus[tabId]) return tabStatus[tabId];
  try {
    const r = await chrome.storage.session.get([`tab_${tabId}`]);
    return r[`tab_${tabId}`] || null;
  } catch (_) { return null; }
}
async function removeTabStatus(tabId) {
  delete tabStatus[tabId];
  try { await chrome.storage.session.remove([`tab_${tabId}`]); } catch (_) {}
}

// ============================================================
// RATE LIMITER
// ============================================================
const ipApiQueue = [];
let ipApiRunning = 0;
const IP_API_CONCURRENCY = 2;
const IP_API_DELAY_MS = 1400;

function ipApiRateLimited(ip) {
  return new Promise((resolve) => {
    ipApiQueue.push({ ip, resolve });
    drainIpApiQueue();
  });
}
async function drainIpApiQueue() {
  if (ipApiRunning >= IP_API_CONCURRENCY || ipApiQueue.length === 0) return;
  ipApiRunning++;
  const { ip, resolve } = ipApiQueue.shift();
  try { resolve(await fetchIPOrgRaw(ip)); }
  catch (e) { resolve(null); }
  finally { ipApiRunning--; setTimeout(drainIpApiQueue, IP_API_DELAY_MS); }
}

// ============================================================
// REDIRECT CHAIN TRACKING
// ============================================================
const redirectChains = {};

chrome.webRequest.onBeforeRedirect.addListener(
  (details) => {
    if (details.tabId < 0) return;
    if (!redirectChains[details.tabId]) redirectChains[details.tabId] = [];
    redirectChains[details.tabId].push({
      from: details.url,
      to: details.redirectUrl,
      statusCode: details.statusCode,
      timestamp: Date.now()
    });
    if (redirectChains[details.tabId].length > 10) {
      redirectChains[details.tabId].shift();
    }
  },
  { urls: ["<all_urls>"], types: ["main_frame"] }
);

chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
  if (changeInfo.status === "loading") {
    if (!redirectChains[tabId]) redirectChains[tabId] = [];
  }
});

chrome.tabs.onRemoved.addListener((tabId) => {
  removeTabStatus(tabId);
  delete redirectChains[tabId];
});

function analyzeRedirectChain(tabId, finalUrl) {
  const chain = redirectChains[tabId] || [];
  if (chain.length === 0) return { chain: [], suspicious: false, flags: [] };

  const flags = [];
  const finalHostname = safeHostname(finalUrl);

  const domains = new Set();
  chain.forEach(r => {
    const h = safeHostname(r.from);
    if (h) domains.add(h);
  });
  if (finalHostname) domains.add(finalHostname);

  const uniqueDomains = [...domains];

  if (chain.length >= 3) {
    flags.push(`Long redirect chain (${chain.length} hops) — common in phishing`);
  }

  const hasHttpDowngrade = chain.some(r =>
    r.from.startsWith("https://") && r.to.startsWith("http://")
  );
  if (hasHttpDowngrade) flags.push("Redirect downgrades HTTPS → HTTP (insecure)");

  if (uniqueDomains.length > 1) {
    const nonFinalDomains = uniqueDomains.filter(d => d !== finalHostname);
    const collegeRelatedFinal = PHISHING_KEYWORDS_match(finalHostname || "");
    if (collegeRelatedFinal && nonFinalDomains.length > 0) {
      flags.push(`Redirected through ${nonFinalDomains.length} other domain(s) to reach this page`);
    }
  }

  return {
    chain,
    hops: chain.length,
    domainsInvolved: uniqueDomains,
    suspicious: flags.length > 0,
    flags
  };
}

function safeHostname(url) {
  try { return new URL(url).hostname.toLowerCase(); } catch (_) { return null; }
}

// ============================================================
// MAIN TAB ANALYSIS
// ============================================================
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (changeInfo.status === "complete" && tab.url) {
    try {
      const url = new URL(tab.url);
      if (url.protocol !== "https:" && url.protocol !== "http:") return;

      const hostname = url.hostname.toLowerCase();
      await setTabStatus(tabId, { status: "checking", hostname, url: tab.url });
      updateBadge(tabId, "checking");

      await loadConfig();
      
      let finalResult = null; 

      // STEP 1: Official college domain?
      const isOfficialDomain = isOnWhitelist(hostname, CONFIG.TRUSTED_DOMAINS);
      if (isOfficialDomain) {
        const isHttps = url.protocol === "https:";
        const resolvedIPs = await resolveHostname(hostname);
        const ipCheck = await checkIPMatch(resolvedIPs, CONFIG.TRUSTED_IPS);
        const ipMatchesTrusted = ipCheck.matched;

        const [sslInfo, domainAge, redirectInfo] = await Promise.all([
          checkSSLCertificate(hostname, isHttps),
          checkDomainAge(hostname),
          Promise.resolve(analyzeRedirectChain(tabId, tab.url))
        ]);

        const flags = [];
        if (!isHttps) flags.push("Official domain but no SSL — insecure");
        if (sslInfo.suspicious) flags.push(...sslInfo.flags);
        if (redirectInfo.suspicious) flags.push(...redirectInfo.flags);

        const status = isHttps && flags.length === 0 ? "safe" : flags.length > 0 ? "warning" : "safe";
        const reason = status === "safe"
          ? "Official college domain with valid HTTPS."
          : flags.join(" • ");

        finalResult = {
          status, reason, hostname, isOfficialDomain: true, isWhitelisted: false, isHttps,
          resolvedIPs, ipMatchesTrusted,
          ipCheckMethod: ipCheck.method, ipCheckOrg: ipCheck.org || null,
          typosquatMatch: { detected: false }, flags,
          sslInfo, domainAge, redirectInfo,
          url: tab.url, timestamp: Date.now()
        };
      }
      // STEP 2: On global/user whitelist?
      else if (isOnWhitelist(hostname, CONFIG.WHITELIST)) {
        finalResult = {
          status: "safe", reason: "This site is on the trusted whitelist.",
          hostname, isOfficialDomain: false, isWhitelisted: true,
          isHttps: url.protocol === "https:", resolvedIPs: [],
          ipMatchesTrusted: false, typosquatMatch: { detected: false },
          flags: [], url: tab.url, timestamp: Date.now()
        };
      }
      else {
        // =========================================================
        // STEP 3: THE GATEKEEPER & SISTER COLLEGE EXCEPTION
        // =========================================================
        const fullUrlString = (hostname + url.pathname).toLowerCase();
        const triggersGate = CONFIG.PHISHING_KEYWORDS.some(kw => fullUrlString.includes(kw));
        
        const isAcademic = isAcademicDomain(hostname);
        const typosquatMatch = detectTyposquat(hostname, CONFIG.TRUSTED_DOMAINS);

        if (!triggersGate) {
          // SITE IS UNRELATED. BYPASS ALL CHECKS.
          finalResult = {
            status: "safe", 
            reason: "Standard website (No academic or login keywords detected).",
            hostname, isOfficialDomain: false, isWhitelisted: false,
            isHttps: url.protocol === "https:", resolvedIPs: [],
            ipMatchesTrusted: false, typosquatMatch: { detected: false }, 
            flags: [], url: tab.url, timestamp: Date.now(),
            gatekeeperIgnored: true  // Forces subsequent logic to ignore this evaluation
          };
        } 
        else if (isAcademic && !typosquatMatch.detected) {
          // SISTER COLLEGE EXCEPTION
          finalResult = {
            status: "safe",
            reason: "Verified sister academic institution.",
            hostname, isOfficialDomain: false, isWhitelisted: false,
            isHttps: url.protocol === "https:", resolvedIPs: [],
            ipMatchesTrusted: false, typosquatMatch: { detected: false },
            flags: [], url: tab.url, timestamp: Date.now(),
            gatekeeperIgnored: true
          };
        }
        else {
          // THE GATE WAS TRIGGERED. RUN FULL PHISHING ANALYSIS.
          const isHttps = url.protocol === "https:";
          const [resolvedIPs, sslInfo, domainAge, redirectInfo] = await Promise.all([
            resolveHostname(hostname),
            checkSSLCertificate(hostname, isHttps),
            checkDomainAge(hostname),
            Promise.resolve(analyzeRedirectChain(tabId, tab.url))
          ]);

          const ipCheck = await checkIPMatch(resolvedIPs, CONFIG.TRUSTED_IPS);
          const ipMatchesTrusted = ipCheck.matched;

          const flags = [];
          if (typosquatMatch.detected) flags.push(`Looks like a fake copy of "${typosquatMatch.matchedDomain}"`);
          if (!ipMatchesTrusted) flags.push("Uses target keywords, but IP does not belong to college servers");
          if (!isHttps) flags.push("No SSL/HTTPS — connection is insecure");
          if (sslInfo.suspicious) flags.push(...sslInfo.flags);
          if (domainAge.suspicious) flags.push(...domainAge.flags);
          if (redirectInfo.suspicious) flags.push(...redirectInfo.flags);

          const status = (typosquatMatch.detected || domainAge.suspicious) ? "danger" : "warning";
          const reason = flags.join(" • ") || "Triggered keyword watch-list; unverified host.";

          finalResult = {
            status, reason, hostname, resolvedIPs, isHttps,
            isOfficialDomain: false, isWhitelisted: false,
            ipMatchesTrusted, typosquatMatch, flags,
            sslInfo, domainAge, redirectInfo,
            url: tab.url, timestamp: Date.now(),
            gatekeeperIgnored: false
          };
        }
      } // end Step 3 outer else

      // ============================================================
      // UNIFIED OVERRIDE & WARNING LOGIC
      // ============================================================
      if (finalResult) {
        finalResult = applySensitivity(finalResult);

        const override = await getVerdictOverride(hostname);
        if (override) {
          finalResult.status = override.verdict;
          finalResult.reason = `Overridden: ${override.reason || "User forced verdict"}`;
          finalResult.sensitivityAdjusted = false; 
        }

        await setTabStatus(tabId, finalResult);
        updateBadge(tabId, finalResult.status);

        if (finalResult.status === "danger" || finalResult.status === "warning") {
            saveFlaggedSite(finalResult);
        }

        try {
          chrome.runtime.sendMessage({ type: "STATUS_UPDATED", tabId: tabId });
        } catch (_) {}

        if (finalResult.status === "danger" || finalResult.status === "warning") {
          setTimeout(() => {
            chrome.tabs.sendMessage(tabId, {
              type: "SHOW_WARNING",
              status: finalResult.status,
              reason: finalResult.reason,
              flags: finalResult.flags,
              resolvedIPs: finalResult.resolvedIPs,
              trustedIPs: CONFIG.TRUSTED_IPS,
              trustedDomains: CONFIG.TRUSTED_DOMAINS,
              typosquatMatch: finalResult.typosquatMatch, 
              hostname: finalResult.hostname,
              sslInfo: finalResult.sslInfo, 
              domainAge: finalResult.domainAge, 
              redirectInfo: finalResult.redirectInfo,
              sensitivityAdjusted: finalResult.sensitivityAdjusted || false,
              originalStatus: finalResult.originalStatus || null
            }, () => { void chrome.runtime.lastError; });
          }, 800);
        }
      }
    } catch (e) {
      console.error("Login Guard error:", e);
    }
  }
});

// ============================================================
// MESSAGE HANDLERS
// ============================================================
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === "GET_STATUS") {
    getTabStatus(msg.tabId).then(s => sendResponse(s || { status: "unknown" }));
    return true;
  }
  if (msg.type === "GET_HISTORY") {
    chrome.storage.local.get(["flaggedSites"], (data) => {
      sendResponse(data.flaggedSites || []);
    });
    return true;
  }
  if (msg.type === "CLEAR_HISTORY") {
    chrome.storage.local.set({ flaggedSites: [] }, () => sendResponse({ ok: true }));
    return true;
  }
  if (msg.type === "ADD_TO_WHITELIST") {
    chrome.storage.sync.get(["userWhitelist"], (data) => {
      const list = data.userWhitelist || [];
      if (!list.includes(msg.hostname)) {
        list.push(msg.hostname);
        chrome.storage.sync.set({ userWhitelist: list }, () => sendResponse({ ok: true }));
      } else { sendResponse({ ok: true }); }
    });
    return true;
  }
  if (msg.type === "GET_USER_WHITELIST") {
    chrome.storage.sync.get(["userWhitelist"], (data) => {
      sendResponse(data.userWhitelist || []);
    });
    return true;
  }
  if (msg.type === "REMOVE_FROM_WHITELIST") {
    chrome.storage.sync.get(["userWhitelist"], (data) => {
      const list = (data.userWhitelist || []).filter(d => d !== msg.hostname);
      chrome.storage.sync.set({ userWhitelist: list }, () => sendResponse({ ok: true }));
    });
    return true;
  }
  if (msg.type === "REPORT_SITE") {
    const tabId = msg.tabId || sender.tab?.id;
    getTabStatus(tabId).then(s => {
      if (s) saveFlaggedSite({ ...s, reported: true });
      sendResponse({ ok: true });
    });
    return true;
  }
  if (msg.type === "FORM_ACTION_EXTERNAL") {
    const tabId = sender.tab?.id;
    if (!tabId) return;

    // Never flag external form actions on official college domains or whitelisted pages.
    // e.g. blog.kct.ac.in using a FeedBurner subscribe form is completely legitimate.
    const pageHostname = (msg.hostname || "").toLowerCase();
    const isOfficialPage = isOnWhitelist(pageHostname, CONFIG.TRUSTED_DOMAINS);
    const isWhitelistedPage = isOnWhitelist(pageHostname, CONFIG.WHITELIST);
    if (isOfficialPage || isWhitelistedPage) return;

    // Also skip if the form's target domain itself is on the trusted list.
    const isTrustedFormDomain = TRUSTED_FORM_DOMAINS.some(d => msg.externalDomain.endsWith(d));
    if (isTrustedFormDomain) {
      console.log("Safe form submission detected to:", msg.externalDomain);
      return;
    }

    getTabStatus(tabId).then(async s => {
      // Skip if this tab is already confirmed safe (official/whitelisted) or already danger.
      if (s && (s.status === "danger" || s.isOfficialDomain || s.isWhitelisted)) return;
      const result = {
        status: "danger",
        reason: `Form submits to external domain: ${msg.externalDomain}`,
        hostname: msg.hostname,
        resolvedIPs: s?.resolvedIPs || [],
        isHttps: msg.isHttps,
        isOfficialDomain: false, isWhitelisted: false, ipMatchesTrusted: false,
        typosquatMatch: { detected: false },
        flags: [`Form action points to unknown domain: ${msg.externalDomain}`],
        url: s?.url || "", timestamp: Date.now()
      };
      await setTabStatus(tabId, result);
      updateBadge(tabId, "danger");
      saveFlaggedSite(result);
      chrome.tabs.sendMessage(tabId, {
        type: "SHOW_WARNING",
        status: "danger", reason: result.reason, flags: result.flags,
        resolvedIPs: [], trustedIPs: CONFIG.TRUSTED_IPS,
        trustedDomains: CONFIG.TRUSTED_DOMAINS,
        typosquatMatch: { detected: false }, hostname: msg.hostname
      }, () => {
        // Swallows the connection error
        if (chrome.runtime.lastError) {
          // Silently ignore
        }
      });
    });
    return true;
  }
  
  return true;
});

// ============================================================
// HELPERS
// ============================================================
function isAcademicDomain(hostname) {
  return hostname.endsWith(".ac.in") || hostname.endsWith(".edu.in");
}
function isOnWhitelist(hostname, list) {
  return list.some(d => hostname === d || hostname.endsWith("." + d));
}

function PHISHING_KEYWORDS_match(hostname) {
  return CONFIG.PHISHING_KEYWORDS.some(kw => hostname.includes(kw));
}

function detectTyposquat(hostname, referenceList) {
  const hostBase = hostname.split(".")[0];
  const isAcademic = isAcademicDomain(hostname);

  for (const trusted of referenceList) {
    const trustedBase = trusted.split(".")[0];
    if (hostname === trusted || hostname.endsWith("." + trusted)) continue;

    // If it's an official academic site, skip the math-heavy typosquatting alerts
    if (isAcademic) continue;

    if (trustedBase.length >= 3 && hostBase.includes(trustedBase)) {
      return { detected: true, matchedDomain: trusted };
    }
    if (trustedBase.length >= 3 && levenshtein(hostBase, trustedBase) <= 1) {
      return { detected: true, matchedDomain: trusted };
    }
  }
  return { detected: false };
}

function levenshtein(a, b) {
  const dp = Array.from({ length: a.length + 1 }, (_, i) =>
    Array.from({ length: b.length + 1 }, (_, j) => (i === 0 ? j : j === 0 ? i : 0))
  );
  for (let i = 1; i <= a.length; i++)
    for (let j = 1; j <= b.length; j++)
      dp[i][j] = a[i-1] === b[j-1] ?
        dp[i-1][j-1] : 1 + Math.min(dp[i-1][j], dp[i][j-1], dp[i-1][j-1]);
  return dp[a.length][b.length];
}

function saveFlaggedSite(result) {
  chrome.storage.local.get(["flaggedSites"], (data) => {
    const sites = data.flaggedSites || [];
    const recent = sites.find(s => s.hostname === result.hostname && Date.now() - s.timestamp < 600000);
    if (!recent) {
      sites.unshift({
        hostname: result.hostname, url: result.url, status: result.status,
        reason: result.reason, flags: result.flags, timestamp: result.timestamp || Date.now()
      });
      chrome.storage.local.set({ flaggedSites: sites.slice(0, 50) });
    }
  });
}

function updateBadge(tabId, status) {
  const cfg = {
    safe:     { text: "✓", color: "#22c55e" },
    warning:  { text: "!", color: "#f59e0b" },
    danger:   { text: "✗", color: "#ef4444" },
    checking: { text: "…", color: "#6b7280" },
    unknown:  { text: "?", color: "#6b7280" }
  }[status] || { text: "?", color: "#6b7280" };
  chrome.action.setBadgeText({ text: cfg.text, tabId });
  chrome.action.setBadgeBackgroundColor({ color: cfg.color, tabId });
}

// ============================================================
// DNS RESOLUTION
// ============================================================
async function resolveViaMXToolbox(hostname) {
  try {
    const res = await fetch(`https://api.hackertarget.com/dnslookup/?q=${encodeURIComponent(hostname)}`);
    if (!res.ok) return [];
    const text = await res.text();
    if (text.startsWith("error") || text.includes("API count exceeded")) return [];
    const ips = [];
    for (const line of text.split("\n")) {
      const match = line.match(/\bA\s+([\d.]+)/);
      if (match) ips.push(match[1]);
    }
    return ips;
  } catch (e) { return []; }
}

async function resolveViaCloudflare(hostname) {
  try {
    const res = await fetch(
      `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(hostname)}&type=A`,
      { headers: { Accept: "application/dns-json" } }
    );
    const data = await res.json();
    if (data.Answer) return data.Answer.filter(r => r.type === 1).map(r => r.data);
  } catch (e) {}
  return [];
}

async function resolveHostname(hostname) {
  const [mxIPs, cfIPs] = await Promise.all([
    resolveViaMXToolbox(hostname),
    resolveViaCloudflare(hostname)
  ]);
  return [...new Set([...mxIPs, ...cfIPs])];
}

async function fetchIPOrgRaw(ip) {
  try {
    const res = await fetch(`https://ip-api.com/json/${ip}?fields=org,as,isp`);
    if (!res.ok) return null;
    const data = await res.json();
    if (data.status === "fail") return null;
    return { org: data.org || "", asn: (data.as || "").split(" ")[0] };
  } catch (e) { return null; }
}

function fetchIPOrg(ip) { return ipApiRateLimited(ip); }

async function checkIPMatch(resolvedIPs, trustedIPs) {
  // 1. Quick check: If any resolved IP is in the hardcoded trusted list, pass instantly.
  for (const ip of resolvedIPs) {
    if (trustedIPs.includes(ip)) return { matched: true, method: "exact" };
  }
  
  if (resolvedIPs.length === 0 || trustedIPs.length === 0) return { matched: false, method: "none" };

  // 2. ASN check: Get the organization info for the resolved IPs and the trusted IPs
  const [resolvedOrgs, trustedOrgs] = await Promise.all([
    Promise.all(resolvedIPs.slice(0, 3).map(fetchIPOrg)),
    Promise.all(trustedIPs.slice(0, 4).map(fetchIPOrg))
  ]);

  const resolvedASNs = resolvedOrgs.filter(Boolean).map(o => o.asn).filter(Boolean);
  const trustedASNs = new Set(trustedOrgs.filter(Boolean).map(o => o.asn).filter(Boolean));

  // 3. If the ASN matches, we trust it regardless of the specific IP
  for (const asn of resolvedASNs) {
    if (trustedASNs.has(asn)) {
      return { matched: true, method: "asn", matchedASN: asn };
    }
  }

  return { matched: false, method: "none" };
}

// ============================================================
// FEATURE: SSL CERTIFICATE ANALYSIS
// ============================================================
async function checkSSLCertificate(hostname, isHttps) {
  if (!isHttps) {
    return {
      hasSSL: false,
      suspicious: true,
      flags: ["Site has no SSL certificate — plain HTTP"],
      grade: "F"
    };
  }

  try {
    const res = await fetch(
      `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(hostname)}&type=HTTPS`,
      { headers: { Accept: "application/dns-json" } }
    );
    const data = await res.json();
    const hasHTTPSRecord = data.Answer && data.Answer.length > 0;

    const caaRes = await fetch(
      `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(hostname)}&type=CAA`,
      { headers: { Accept: "application/dns-json" } }
    );
    const caaData = await caaRes.json();
    const hasCAA = caaData.Answer && caaData.Answer.length > 0;

    const caaIssuers = hasCAA
      ? caaData.Answer.filter(r => r.data && r.data.includes("issue")).map(r => r.data)
      : [];

    const flags = [];
    let suspicious = false;

    if (!hasHTTPSRecord && !hasCAA) {
      flags.push("No HTTPS DNS record — SSL may be self-signed or misconfigured");
      suspicious = true;
    }

    const phishingFriendlyCAs = ["letsencrypt.org", "zerossl.com", "buypass.com"];
    const isPhishingFriendlyCA = caaIssuers.some(c =>
      phishingFriendlyCAs.some(pca => c.includes(pca))
    );

    if (isPhishingFriendlyCA && !hasHTTPSRecord) {
      flags.push("SSL issued by free CA (common in phishing sites)");
      suspicious = true;
    }

    const grade = suspicious ? "C" : hasHTTPSRecord && hasCAA ? "A" : "B";

    return {
      hasSSL: true,
      hasHTTPSRecord,
      hasCAA,
      caaIssuers,
      suspicious,
      flags,
      grade
    };
  } catch (e) {
    return {
      hasSSL: isHttps,
      suspicious: false,
      flags: [],
      grade: isHttps ? "B" : "F",
      error: "Could not analyze SSL"
    };
  }
}

// ============================================================
// FEATURE: DOMAIN AGE CHECK
// ============================================================
async function checkDomainAge(hostname) {
  const parts = hostname.split(".");
  const registrableDomain = parts.length >= 2 ? parts.slice(-2).join(".") : hostname;

  try {
    const rdapUrl = `https://rdap.org/domain/${encodeURIComponent(registrableDomain)}`;
    const res = await fetch(rdapUrl, { signal: AbortSignal.timeout(5000) });
    if (!res.ok) throw new Error(`RDAP ${res.status}`);

    const data = await res.json();
    let createdDate = null;
    let updatedDate = null;
    let expiresDate = null;

    if (data.events) {
      for (const event of data.events) {
        if (event.eventAction === "registration") createdDate = event.eventDate;
        if (event.eventAction === "last changed") updatedDate = event.eventDate;
        if (event.eventAction === "expiration") expiresDate = event.eventDate;
      }
    }

    if (!createdDate) {
      return { checked: true, suspicious: false, flags: [], reason: "Registration date not found" };
    }

    const created = new Date(createdDate);
    const ageMs = Date.now() - created.getTime();
    const ageDays = Math.floor(ageMs / (1000 * 60 * 60 * 24));
    const ageMonths = Math.floor(ageDays / 30);
    const flags = [];
    let suspicious = false;

    if (ageDays < 30) {
      flags.push(`Domain is only ${ageDays} day(s) old — very new domains are a major phishing signal`);
      suspicious = true;
    } else if (ageDays < 90) {
      flags.push(`Domain is only ${ageDays} days old (${ageMonths} months) — recent registration`);
      suspicious = true;
    }

    const registrar = data.entities
      ? data.entities.find(e => e.roles?.includes("registrar"))?.vcardArray?.[1]
        ?.find(v => v[0] === "fn")?.[3] || null
      : null;

    return {
      checked: true,
      suspicious,
      flags,
      ageDays,
      ageMonths,
      createdDate,
      updatedDate,
      expiresDate,
      registrar,
      domain: registrableDomain
    };
  } catch (e) {
    try {
      const tld = hostname.split(".").pop();
      if (["com", "net"].includes(tld)) {
        const res2 = await fetch(
          `https://rdap.verisign.com/${tld}/v1/domain/${encodeURIComponent(registrableDomain)}`,
          { signal: AbortSignal.timeout(4000) }
        );
        if (res2.ok) {
          const data2 = await res2.json();
          let createdDate = null;
          if (data2.events) {
            const reg = data2.events.find(e => e.eventAction === "registration");
            if (reg) createdDate = reg.eventDate;
          }
          if (createdDate) {
            const ageDays = Math.floor((Date.now() - new Date(createdDate).getTime()) / 86400000);
            const flags = [];
            let suspicious = false;
            if (ageDays < 30) { flags.push(`Domain is only ${ageDays} day(s) old — very new`);
              suspicious = true; }
            else if (ageDays < 90) { flags.push(`Domain is only ${ageDays} days old — recent registration`);
              suspicious = true; }
            return { checked: true, suspicious, flags, ageDays, createdDate, domain: registrableDomain };
          }
        }
      }
    } catch (_) {}

    return { checked: false, suspicious: false, flags: [], reason: "Domain age lookup failed" };
  }
}

// ============================================================
// SENSITIVITY THRESHOLDS
// ============================================================
const SENSITIVITY_THRESHOLDS = {
  1: { warn: 52, danger: 80 }, 
  2: { warn: 38, danger: 65 }, 
  3: { warn: 25, danger: 50 }, 
  4: { warn: 16, danger: 37 }, 
  5: { warn:  8, danger: 25 }, 
};

function applySensitivity(result) {
  // ESCAPE HATCH: If the domain was ignored by the Gatekeeper, don't change its state!
  if (result.isOfficialDomain || result.isWhitelisted || result.gatekeeperIgnored) return result;

  const level = Math.max(1, Math.min(5, CONFIG.SENSITIVITY_LEVEL || 3));
  const { warn, danger } = SENSITIVITY_THRESHOLDS[level] || SENSITIVITY_THRESHOLDS[3];
  const score = calculateRiskScore(result);

  let adjustedStatus;
  if (score >= danger)      adjustedStatus = "danger";
  else if (score >= warn)   adjustedStatus = "warning";
  else                      adjustedStatus = "safe";

  if (adjustedStatus === result.status) return result;

  return {
    ...result,
    status: adjustedStatus,
    sensitivityAdjusted: true,
    originalStatus: result.status,
    riskScore: score,
    reason: result.reason
      ? `${result.reason} [Sensitivity L${level}: risk score ${score}]`
      : `Sensitivity L${level}: risk score ${score}`
  };
}

function calculateRiskScore(result) {
  if (!result) return 0;
  if (result.gatekeeperIgnored) return 0; // The Gatekeeper already verified this is safe
  if (result.status === "safe" && result.isOfficialDomain) return 2;
  if (result.isWhitelisted) return 5;

  let score = 0;

  // 1. Reduce points for "Not Official Domain"
  // If it's an academic site, give it a discount (5 pts instead of 10)
  const isAcademic = isAcademicDomain(result.hostname);
  const domainPenalty = isAcademic ? 5 : 10; 
  if (!result.isOfficialDomain) score += domainPenalty;

  // 2. Reduce points for "IP Mismatch"
  // Sister colleges won't have your college IPs, but shouldn't be penalized heavily
  const ipPenalty = isAcademic ? 5 : 10;
  if (!result.ipMatchesTrusted && !result.isOfficialDomain) score += ipPenalty;

  // Keep existing checks for high-risk items (Typosquatting/SSL are REAL threats)
  if (result.typosquatMatch?.detected) score += 30;
  if (!result.isHttps) score += 20;
  if (result.sslInfo?.suspicious) score += 10;
  if (result.sslInfo?.grade === "F") score += 15;
  if (result.domainAge?.suspicious) {
    const ageDays = result.domainAge.ageDays || 0;
    score += ageDays < 7 ? 30 : ageDays < 30 ? 20 : 10;
  }
  if (result.redirectInfo?.suspicious) score += 10;
  if ((result.redirectInfo?.hops || 0) >= 3) score += 5;

  const flagCount = (result.flags || []).length;
  score += Math.min(flagCount * 3, 15);

  return Math.min(score, 100);
}

// ============================================================
// VERDICT OVERRIDE
// ============================================================
async function saveVerdictOverride(hostname, override) {
  return new Promise(resolve => {
    chrome.storage.local.get(["verdictOverrides"], (data) => {
      const overrides = data.verdictOverrides || {};
      if (override === null) {
        delete overrides[hostname];
      } else {
        overrides[hostname] = { ...override, timestamp: Date.now() };
      }
      chrome.storage.local.set({ verdictOverrides: overrides }, () => resolve({ ok: true }));
    });
  });
}

async function getVerdictOverride(hostname) {
  return new Promise(resolve => {
    chrome.storage.local.get(["verdictOverrides"], (data) => {
      const overrides = data.verdictOverrides || {};
      resolve(overrides[hostname] || null);
    });
  });
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === "GET_RISK_SCORE") {
    getTabStatus(msg.tabId).then(s => {
      sendResponse({ score: calculateRiskScore(s), status: s?.status || "unknown" });
    });
    return true;
  }
  if (msg.type === "SAVE_VERDICT_OVERRIDE") {
    saveVerdictOverride(msg.hostname, msg.override).then(r => sendResponse(r));
    return true;
  }
  if (msg.type === "GET_VERDICT_OVERRIDE") {
    getVerdictOverride(msg.hostname).then(r => sendResponse(r));
    return true;
  }
  if (msg.type === "CLEAR_VERDICT_OVERRIDE") {
    saveVerdictOverride(msg.hostname, null).then(r => sendResponse(r));
    return true;
  }
  if (msg.type === "GET_ALL_VERDICT_OVERRIDES") {
    chrome.storage.local.get(["verdictOverrides"], (data) => {
      sendResponse(data.verdictOverrides || {});
    });
    return true;
  }
  
  if (msg.type === "PASSWORD_FIELD_DETECTED") {
    const tabId = sender.tab?.id;
    if (!tabId) { sendResponse({ ok: true }); return true; }
    getTabStatus(tabId).then(async s => {
      if (!s) return;
      if (!msg.isHttps && s.status === "safe") {
        const flagText = `Password field on HTTP page (${msg.fieldCount} field${msg.fieldCount > 1 ? "s" : ""})`;
        const newFlags = [...(s.flags || [])];
        if (!newFlags.includes(flagText)) newFlags.push(flagText);
        const updated = { ...s, status: "warning", reason: flagText, flags: newFlags };
        await setTabStatus(tabId, updated);
        updateBadge(tabId, "warning");
        saveFlaggedSite(updated);
      }
    });
    sendResponse({ ok: true });
    return true;
  }

  if (msg.type === "EXPORT_CONFIG") {
    chrome.storage.sync.get(null, (syncData) => {
      chrome.storage.local.get(["flaggedSites", "verdictOverrides"], (localData) => {
        const exportObj = {
          _meta: {
            exportedAt: new Date().toISOString(),
            version: "1.1",
            extension: "College Login Guard"
          },
          sync: syncData,
          history: {
            flaggedSites: localData.flaggedSites || [],
            verdictOverrides: localData.verdictOverrides || {}
          }
        };
        sendResponse({ ok: true, data: exportObj });
      });
    });
    return true;
  }

  if (msg.type === "IMPORT_CONFIG") {
    try {
      const cfg = msg.config;
      if (!cfg || !cfg.sync || typeof cfg.sync !== "object") {
        sendResponse({ ok: false, error: "Invalid config file — missing sync data." });
        return true;
      }
      const syncToWrite = { ...cfg.sync };
      chrome.storage.sync.set(syncToWrite, () => {
        if (chrome.runtime.lastError) {
          sendResponse({ ok: false, error: chrome.runtime.lastError.message }); return;
        }
        const localToWrite = {};
        if (cfg.history?.flaggedSites) localToWrite.flaggedSites = cfg.history.flaggedSites;
        if (cfg.history?.verdictOverrides) localToWrite.verdictOverrides = cfg.history.verdictOverrides;
        if (Object.keys(localToWrite).length > 0) {
          chrome.storage.local.set(localToWrite, () => sendResponse({ ok: true }));
        } else {
          sendResponse({ ok: true });
        }
      });
    } catch (e) {
      sendResponse({ ok: false, error: e.message });
    }
    return true;
  }

  if (msg.type === "EXPORT_REPORT") {
    chrome.storage.local.get(["flaggedSites", "verdictOverrides"], (data) => {
      sendResponse({
        flaggedSites: data.flaggedSites || [],
        verdictOverrides: data.verdictOverrides || {}
      });
    });
    return true;
  }
  return true; 
});