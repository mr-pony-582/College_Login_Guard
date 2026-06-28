// ============================================================
// ONBOARDING SCRIPT 
// ============================================================

let currentStep = 0;
const TOTAL = 4;

function goStep(n) {
  document.getElementById('step-' + currentStep).classList.remove('active');
  for (let i = 0; i < TOTAL; i++) {
    const dot = document.getElementById('dot-' + i);
    if(dot) {
      dot.className = 'dot' + (i < n ? ' done' : i === n ? ' active' : '');
    }
  }
  currentStep = n;
  document.getElementById('step-' + n).classList.add('active');
}

// Resolve IPs for a list of domains using HackerTarget + Cloudflare DoH
// (same logic as popup.js Save Settings so the stored IPs always match)
async function resolveDomainsToIPs(domains) {
  const ipSet = new Set();

  for (const domain of domains) {
    // HackerTarget DNS lookup
    try {
      const res = await fetch(`https://api.hackertarget.com/dnslookup/?q=${encodeURIComponent(domain)}`);
      const text = await res.text();
      if (!text.startsWith("error") && !text.includes("API count exceeded")) {
        for (const line of text.split("\n")) {
          const m = line.match(/\bA\s+([\d.]+)/);
          if (m) ipSet.add(m[1]);
        }
      }
    } catch (_) {}

    // Cloudflare DoH fallback
    try {
      const res = await fetch(
        `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=A`,
        { headers: { Accept: "application/dns-json" } }
      );
      const data = await res.json();
      if (data.Answer) {
        data.Answer.filter(r => r.type === 1).forEach(r => ipSet.add(r.data));
      }
    } catch (_) {}
  }

  return [...ipSet];
}

async function finish() {
  const domainsRaw = document.getElementById('ob-domains').value;
  const domains = domainsRaw.split('\n').map(s => s.trim().toLowerCase()).filter(Boolean);
  
  if (domains.length === 0) {
    const msg = document.getElementById('ob-msg');
    msg.style.color = '#f87171';
    msg.textContent = '⚠ Please enter at least one domain.';
    msg.style.display = 'block';
    return;
  }

  const finishBtn = document.getElementById('btn-finish');
  const msg = document.getElementById('ob-msg');

  // Show resolving state
  finishBtn.disabled = true;
  finishBtn.textContent = '⏳ Resolving IPs…';
  msg.style.color = '#60a5fa';
  msg.textContent = 'Looking up your college\'s IP addresses — this takes a few seconds…';
  msg.style.display = 'block';

  // Resolve IPs the same way Save Settings does
  const resolvedIPs = await resolveDomainsToIPs(domains);

  // Save domains + IPs together (same keys popup.js Save Settings uses)
  await new Promise(resolve =>
    chrome.storage.sync.set(
      { trustedDomains: domains, trustedIPs: resolvedIPs, onboardingDone: true },
      resolve
    )
  );

  msg.style.color = '#4ade80';
  msg.textContent = resolvedIPs.length > 0
    ? `✓ All set! Saved ${resolvedIPs.length} IPs. Closing…`
    : '✓ All set! No IPs resolved yet — open Settings to retry later. Closing…';
  finishBtn.textContent = '✓ Start Protecting Me';

  setTimeout(() => window.close(), 1600);
}

// Bind event listeners when the DOM is fully loaded to comply with MV3 rules
document.addEventListener('DOMContentLoaded', () => {
  // Navigation Buttons
  document.getElementById('btn-start').addEventListener('click', () => goStep(1));
  
  document.getElementById('btn-back-1').addEventListener('click', () => goStep(0));
  document.getElementById('btn-next-1').addEventListener('click', () => goStep(2));
  
  document.getElementById('btn-back-2').addEventListener('click', () => goStep(1));
  document.getElementById('btn-next-2').addEventListener('click', () => goStep(3));
  
  document.getElementById('btn-back-3').addEventListener('click', () => goStep(2));

  // Action Buttons
  document.getElementById('btn-finish').addEventListener('click', finish);
});
