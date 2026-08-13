// Inglorious Network Scanner — dashboard front-end.
// Plain vanilla JS, no framework. Calm-guardian redesign: 4 tabs
// (Overview / Devices / Activity / Settings), typographic status statement,
// stroke iconography, severity color on a strict budget.

const $  = (sel) => document.querySelector(sel);
const $$ = (sel) => Array.from(document.querySelectorAll(sel));

const RISKY_PORTS = new Set([23, 21, 513, 514, 111, 2049, 3389, 5900, 6667, 1080]);

// ── iconography ───────────────────────────────────────────────────────────
// One drawn stroke set for severity + device types. 24px grid, 1.6 stroke,
// round caps — a single visual voice across the whole surface (no emoji).
const _svg = (inner, w = 18) =>
  `<svg viewBox="0 0 24 24" width="${w}" height="${w}" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${inner}</svg>`;

const SEV_ICON = {
  critical: _svg('<circle cx="12" cy="12" r="9.25"/><path d="M12 8v5"/><circle cx="12" cy="16.4" r=".7" fill="currentColor" stroke="none"/>'),
  warning:  _svg('<path d="M10.66 3.62 1.95 18.5a1.55 1.55 0 0 0 1.34 2.33h17.42a1.55 1.55 0 0 0 1.34-2.33L13.34 3.62a1.55 1.55 0 0 0-2.68 0Z"/><path d="M12 10v4"/><circle cx="12" cy="17.4" r=".7" fill="currentColor" stroke="none"/>'),
  info:     _svg('<circle cx="12" cy="12" r="9.25"/><path d="M12 11.2v4.6"/><circle cx="12" cy="8.2" r=".75" fill="currentColor" stroke="none"/>'),
  ok:       _svg('<circle cx="12" cy="12" r="9.25"/><path d="m8.2 12.4 2.6 2.6 5-5.4"/>'),
};

const DEVICE_ICONS = {
  router:      _svg('<rect x="3" y="12.5" width="18" height="6.5" rx="2"/><path d="M7.5 12.5V8.5M16.5 12.5v-6"/><circle cx="7" cy="15.8" r=".75" fill="currentColor" stroke="none"/><circle cx="10.4" cy="15.8" r=".75" fill="currentColor" stroke="none"/>'),
  access_point:_svg('<circle cx="12" cy="15.5" r="1.3" fill="currentColor" stroke="none"/><path d="M8.6 12.2a4.8 4.8 0 0 1 6.8 0M5.8 9.3a8.8 8.8 0 0 1 12.4 0"/><path d="M12 16.8V20"/>'),
  printer:     _svg('<path d="M7 8.5V4.5h10v4"/><path d="M7 15H5.5A1.5 1.5 0 0 1 4 13.5v-3A1.5 1.5 0 0 1 5.5 9h13a1.5 1.5 0 0 1 1.5 1.5v3a1.5 1.5 0 0 1-1.5 1.5H17"/><rect x="7" y="13" width="10" height="6.5" rx="1"/><circle cx="17.4" cy="11.4" r=".75" fill="currentColor" stroke="none"/>'),
  camera:      _svg('<circle cx="12" cy="10.6" r="5.6"/><circle cx="12" cy="10.6" r="1.9"/><path d="M8.8 15.4 7.2 20h9.6l-1.6-4.6"/>'),
  tv:          _svg('<rect x="3" y="5.5" width="18" height="11.5" rx="1.6"/><path d="M8.5 20.5h7"/>'),
  speaker:     _svg('<rect x="6.5" y="3.5" width="11" height="17" rx="2"/><circle cx="12" cy="14.6" r="3"/><circle cx="12" cy="7.8" r="1.1"/>'),
  phone:       _svg('<rect x="7.5" y="3" width="9" height="18" rx="2.2"/><path d="M10.8 17.8h2.4"/>'),
  tablet:      _svg('<rect x="5" y="3.5" width="14" height="17" rx="2.2"/><path d="M10.8 17.6h2.4"/>'),
  laptop:      _svg('<rect x="4.5" y="5" width="15" height="10" rx="1.6"/><path d="M2.8 18.5h18.4"/>'),
  desktop:     _svg('<rect x="3.5" y="4.5" width="17" height="11.5" rx="1.6"/><path d="M9.5 20.5h5M12 16v4.5"/>'),
  computer:    _svg('<rect x="3.5" y="4.5" width="17" height="11.5" rx="1.6"/><path d="M9.5 20.5h5M12 16v4.5"/>'),
  watch:       _svg('<rect x="7" y="6.5" width="10" height="11" rx="3"/><path d="M9.2 6.5 9.8 3h4.4l.6 3.5M9.2 17.5l.6 3.5h4.4l.6-3.5"/>'),
  console:     _svg('<path d="M6.7 8h10.6c2.4 0 4.2 2 4.2 4.4 0 2.5-1.4 4.6-3 4.6-1.1 0-1.9-.6-2.7-1.5H8.2c-.8.9-1.6 1.5-2.7 1.5-1.6 0-3-2.1-3-4.6C2.5 10 4.3 8 6.7 8Z"/><path d="M8 10.9v3M6.5 12.4h3"/><circle cx="15.8" cy="11.4" r=".75" fill="currentColor" stroke="none"/><circle cx="17.8" cy="13.4" r=".75" fill="currentColor" stroke="none"/>'),
  nas:         _svg('<rect x="4.5" y="4" width="15" height="16" rx="1.6"/><path d="M4.5 9.3h15M4.5 14.6h15"/><circle cx="7.5" cy="6.7" r=".7" fill="currentColor" stroke="none"/><circle cx="7.5" cy="12" r=".7" fill="currentColor" stroke="none"/><circle cx="7.5" cy="17.3" r=".7" fill="currentColor" stroke="none"/>'),
  iot:         _svg('<path d="M9.2 17.6v-1.9C7.3 14.5 6 12.6 6 10.5 6 7.2 8.7 4.5 12 4.5s6 2.7 6 6c0 2.1-1.3 4-3.2 5.2v1.9"/><path d="M9.6 20.5h4.8"/>'),
  voice_assistant:_svg('<rect x="9" y="3" width="6" height="11" rx="3"/><path d="M5.8 11.5a6.2 6.2 0 0 0 12.4 0"/><path d="M12 17.7V21"/>'),
  server:      _svg('<rect x="4" y="4" width="16" height="6.8" rx="1.5"/><rect x="4" y="13.2" width="16" height="6.8" rx="1.5"/><circle cx="7.3" cy="7.4" r=".75" fill="currentColor" stroke="none"/><circle cx="7.3" cy="16.6" r=".75" fill="currentColor" stroke="none"/>'),
  unknown:     _svg('<circle cx="12" cy="12" r="8.6" stroke-dasharray="2.6 3.4"/><path d="M9.8 9.6a2.3 2.3 0 1 1 3.2 2.4c-.7.3-1 .8-1 1.5v.3"/><circle cx="12" cy="16.6" r=".75" fill="currentColor" stroke="none"/>'),
};
const devIcon = (type) => DEVICE_ICONS[type] || DEVICE_ICONS.unknown;

// ── "what does this mean" explainers ──────────────────────────────────────
// Keyed by alert.kind prefix; first matching prefix wins.
const ALERT_HELP = [
  ["rogue_dhcp", {
    title: "More than one DHCP server",
    why:   "Your router hands out IP addresses (DHCP). If two devices are doing that, your network is unstable at best; at worst, someone is intentionally redirecting your traffic.",
    do:    "Most often this is a second router plugged in by mistake. Find anything that isn't your primary router (a powerline adapter, a guest AP, an old base station) and unplug it or switch its DHCP off.",
  }],
  ["arp_flap_", {
    title: "ARP / MAC instability",
    why:   "ARP is how devices on your network find each other. The same IP shouldn't be answered by different hardware in a short window: that's the fingerprint of an ARP-spoofing attack.",
    do:    "If you haven't restarted a router or moved a device recently, take it seriously: change your WiFi password, kick all devices off, and add them back one at a time.",
  }],
  ["vendor_changed", {
    title: "Hardware mismatch on a known MAC",
    why:   "Every network card has a manufacturer tied to its address. If the manufacturer suddenly changes on an address you've seen before, a device is almost certainly pretending to be one of yours.",
    do:    "Change your WiFi password right away, kick everything off the router, and let your real devices reconnect. Whatever doesn't reconnect was probably the impostor.",
  }],
  ["wan_exposed_", {
    title: "Reachable from the public internet",
    why:   "Your router is forwarding a port from the internet to this device. Anyone in the world can try to connect to it. Most homes never need this.",
    do:    "Open your router's admin page and remove the rule under Port Forwarding (sometimes 'NAT / Virtual Server'). While you're there, turn UPnP off so devices can't quietly open ports in the future.",
  }],
  ["default_creds", {
    title: "Likely default password",
    why:   "Some camera and DVR brands ship the same admin password on every unit. If you've never changed it, anyone on your network (or the internet, if exposed) can log in.",
    do:    "Open the device's IP in a browser, log in with the documented default, and set a long unique password. If you can't remember changing it, change it now.",
  }],
  ["risky_port_23", {
    title: "Telnet is exposed",
    why:   "Telnet sends passwords in plain text. No modern device should have it on; a device with Telnet open is either very old or already compromised.",
    do:    "If the device has an admin page, look for a 'disable Telnet' option. If not, treat it as compromised: unplug, factory-reset, update firmware.",
  }],
  ["risky_port_", {
    title: "Insecure protocol exposed",
    why:   "Older remote-access protocols (FTP, RDP, VNC, rsh) have well-known weaknesses or send credentials in plain text. Leaving them open invites break-in attempts.",
    do:    "Disable the service if you don't actively use it. If you do, restrict it to specific source addresses and put it behind a strong password.",
  }],
  ["new_device", {
    title: "A new device joined your WiFi",
    why:   "INS notices the first time it sees a hardware address. If it's yours, name it once and you won't be asked again. If it isn't, your WiFi password may have leaked.",
    do:    "Recognize it? Give it a name on the Devices tab. Don't? Change your WiFi password, kick everything off the router, and re-join your own devices.",
  }],
  ["randomized_mac_", {
    title: "Same device, different address",
    why:   "iPhones, iPads, and modern Android phones rotate their WiFi address for privacy. INS groups them so the same phone doesn't alarm you every week.",
    do:    "If the grouping looks right, nothing to do. If a listed address doesn't belong to that device, investigate it.",
  }],
  ["camera_no_https", {
    title: "Camera admin page is unencrypted",
    why:   "Logging into this camera sends your password in clear text across the network, where any compromised device can capture it.",
    do:    "Look for an HTTPS option in the camera's settings. If there isn't one, treat that password as shared and use it nowhere else.",
  }],
  ["dns_threat", {
    title: "Device contacted a flagged domain",
    why:   "The destination is on a local list of known abuse or malware infrastructure: a strong signal of a compromised device or app.",
    do:    "IoT device: factory-reset it. Computer or phone: run a malware scan and review what's installed.",
  }],
];

// ── state ─────────────────────────────────────────────────────────────────
let STATE   = null;
let HISTORY = [];

const TABS = ["overview", "devices", "activity", "settings"];
// Pre-2.6 tabs map onto the consolidated IA (the menubar opens /#alerts).
const LEGACY_TABS = {
  triage: "devices", alerts: "activity", history: "activity", wifi: "activity",
};
function resolveTab(name) {
  if (TABS.includes(name)) return name;
  return LEGACY_TABS[name] || "overview";
}
let CURRENT_TAB = resolveTab(location.hash.replace("#", ""));

// ── helpers ───────────────────────────────────────────────────────────────
async function api(path, body) {
  const opts = body
    ? { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) }
    : {};
  const r = await fetch(path, opts);
  return r.json();
}
const escHtml = (s) => String(s ?? "").replace(/[&<>"']/g, c =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#39;" }[c]));

function timeAgo(tsSeconds) {
  if (!tsSeconds) return "just now";
  const diff = Date.now() / 1000 - tsSeconds;
  if (diff < 60)      return `${Math.round(diff)}s ago`;
  if (diff < 3600)    return `${Math.round(diff / 60)}m ago`;
  if (diff < 86400)   return `${Math.round(diff / 3600)}h ago`;
  return `${Math.round(diff / 86400)}d ago`;
}

// Best human-readable name: Known label > probe fingerprint > hostname > vendor.
function bestName(d) {
  if (d.known_name)                        return d.known_name;
  if (d.fingerprint)                       return d.fingerprint;
  if (d.hostname && d.hostname !== "—")    return d.hostname.replace(/\.local\.?$/i, "");
  if (d.vendor && d.vendor !== "—")        return d.vendor;
  return "";
}

// ── modal focus management ────────────────────────────────────────────────
let _lastFocus = null;
function _restoreFocus() {
  if (_lastFocus && typeof _lastFocus.focus === "function") _lastFocus.focus();
  _lastFocus = null;
}
function _topmostDialog() {
  for (const id of ["#onboarding", "#device-drawer", "#alert-drawer"]) {
    const el = $(id);
    if (el && !el.hidden) return el;
  }
  return null;
}
const _INERT_SELECTORS = [".app-header", ".app-nav", ".ssid-banner", "main", ".page-footer"];
function _syncModalState() {
  const open = _topmostDialog() !== null;
  _INERT_SELECTORS.forEach(sel => $$(sel).forEach(el => {
    if (open) el.setAttribute("inert", "");
    else      el.removeAttribute("inert");
  }));
}
function _focusables(container) {
  return Array.from(container.querySelectorAll(
    'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), ' +
    'textarea:not([disabled]), [tabindex]:not([tabindex="-1"])'
  )).filter(el => el.offsetParent !== null);
}
function _trapTab(e) {
  const dlg = _topmostDialog();
  if (!dlg) return;
  const f = _focusables(dlg);
  if (!f.length) return;
  const first = f[0], last = f[f.length - 1];
  if (!dlg.contains(document.activeElement)) {
    e.preventDefault(); first.focus();
  } else if (e.shiftKey && document.activeElement === first) {
    e.preventDefault(); last.focus();
  } else if (!e.shiftKey && document.activeElement === last) {
    e.preventDefault(); first.focus();
  }
}

// ── tab switching ─────────────────────────────────────────────────────────
function showTab(name) {
  name = resolveTab(name);
  CURRENT_TAB = name;
  history.replaceState(null, "", `#${name}`);
  $$(".navbtn").forEach(b => {
    const active = b.dataset.tab === name;
    b.classList.toggle("active", active);
    if (active) b.setAttribute("aria-current", "page");
    else        b.removeAttribute("aria-current");
  });
  $$(".tab").forEach(t => t.hidden = t.id !== `tab-${name}`);
  if (name === "activity") loadHistory();
  if (name === "settings") loadRemoteAccess();
  if (STATE) paintActiveTab();
}
$$(".navbtn").forEach(b => b.addEventListener("click", () => showTab(b.dataset.tab)));

// ── refresh loop ──────────────────────────────────────────────────────────
function paintActiveTab() {
  switch (CURRENT_TAB) {
    case "overview": paintStatement(); paintAttention(); paintGlance(); break;
    case "devices":  paintTriage(); paintDevices(); break;
    case "activity": paintAlerts(); drawHistory(); break;
    case "settings": paintWebhooks(); paintHook(); paintSettings(); break;
  }
}

async function refresh() {
  try {
    STATE = await fetch("/api/state").then(r => r.json());
    paintHeader();
    announceNewAlerts();
    paintActiveTab();
    updateLivePill();
  } catch (e) { /* network blip; try again next tick */ }
}

// Coalesce bursty SSE events into a single repaint.
let _refreshTimer = null;
function refreshSoon() {
  if (_refreshTimer) return;
  _refreshTimer = setTimeout(() => { _refreshTimer = null; refresh(); }, 300);
}

async function loadHistory() {
  try {
    HISTORY = await fetch("/api/history?limit=500").then(r => r.json());
  } catch (e) { /* keep whatever we had */ }
  drawHistory();
}

// Screen-reader announcement when the unack count rises.
let _prevUnack = null;
function announceNewAlerts() {
  const el = document.getElementById("a11y-announce");
  if (!el || !STATE) return;
  const n = STATE.unack_count || 0;
  if (_prevUnack !== null && n > _prevUnack) {
    const delta  = n - _prevUnack;
    const newest = (STATE.alerts || [])[0];
    el.textContent = `${delta} new security alert${delta === 1 ? "" : "s"}` +
      (newest && newest.title ? `: ${newest.title}` : "") + ".";
  }
  _prevUnack = n;
}

// ── header ────────────────────────────────────────────────────────────────
function paintHeader() {
  $("#hdr-ssid").textContent  = STATE.ssid || "—";
  $("#hdr-net").textContent   = STATE.network || "—";
  $("#hdr-public-ip").textContent = STATE.public_ip || "—";
  $("#hdr-scantime").textContent = STATE.last_scan && STATE.last_scan !== "—"
    ? `scanned ${STATE.last_scan}` : "—";
  $("#hdr-version").textContent = STATE.version || "";

  const aBadge = $("#nav-alert-badge");
  aBadge.textContent = STATE.unack_count ? STATE.unack_count : "";
  const tBadge = $("#nav-triage-badge");
  tBadge.textContent = (STATE.triage || []).length || "";

  const banner = $("#ssid-banner");
  if (banner) banner.hidden = !(STATE.network && !STATE.ssid);
}

// ── overview: the statement ───────────────────────────────────────────────
const BAND_COPY = {
  excellent: { line: () => `All clear.`,
               sub:  (n, ssid, busy) => busy
                 ? `${n} device${n === 1 ? "" : "s"} on ${ssid || "your network"}. Nothing serious. A little housekeeping below.`
                 : `${n} device${n === 1 ? "" : "s"} on ${ssid || "your network"}. Nothing needs you.` },
  good:      { line: () => `Looking good.`,
               sub:  (n, ssid) => `${n} device${n === 1 ? "" : "s"} on ${ssid || "your network"}. A couple of small things worth a glance below.` },
  fair:      { line: () => `Worth a look.`,
               sub:  () => `A few things on your network deserve attention. None of them are urgent, but don't leave them forever.` },
  poor:      { line: () => `Action needed.`,
               sub:  () => `Something on your network is wrong. Start with the biggest item below.` },
  at_risk:   { line: () => `Your network is at risk.`,
               sub:  () => `Please address the items below now, starting from the top.` },
};

function paintStatement() {
  const el = $("#statement");
  const h = STATE.health;
  const scanning = !STATE.last_scan_epoch;
  const line = $("#statement-line"), sub = $("#statement-sub");
  const meta = $("#statement-meta");
  el.classList.remove("sev-warn", "sev-crit");

  if (scanning || !h || typeof h.score !== "number") {
    line.textContent = "Waiting for the first scan…";
    sub.textContent  = "INS is looking at your network now. This takes a few seconds.";
    meta.hidden = true;
    return;
  }
  const band = h.band || "good";
  const copy = BAND_COPY[band] || BAND_COPY.good;
  const n = STATE.count || 0;
  const busy = (STATE.triage || []).length > 0 ||
               (STATE.alerts || []).some(a => !a.acknowledged);
  line.textContent = copy.line(n, STATE.ssid);
  sub.textContent  = copy.sub(n, STATE.ssid, busy);
  if (band === "fair") el.classList.add("sev-warn");
  if (band === "poor" || band === "at_risk") el.classList.add("sev-crit");

  meta.hidden = false;
  $("#score-chip").innerHTML = `${escHtml(h.score)}<span class="score-denom">/100</span>`;
  const reasons = (h.reasons || []).slice(0, 5);
  $("#statement-reasons").innerHTML = reasons.length
    ? reasons.map(r => `
        <li><span class="reason-weight">−${escHtml(r.weight)}</span>
        <span>${escHtml(r.label)}</span></li>`).join("")
    : `<li><span class="reason-weight"></span><span>Nothing is dragging your score down.</span></li>`;
}

// ── overview: needs-attention list ────────────────────────────────────────
function paintAttention() {
  const list = $("#attention-list");
  // Before the first scan there is nothing honest to say here — hide the
  // section rather than claim "every device has a name" about zero devices.
  const scanned = !!STATE.last_scan_epoch;
  $("#attention-section").hidden = !scanned;
  $("#glance-heading").parentElement.hidden = !scanned;
  if (!scanned) return;
  const items = [];

  for (const d of (STATE.triage || []).slice(0, 4)) {
    const nm = bestName(d);
    items.push({
      kind: "device",
      sev: "info",
      icon: devIcon(d.device_type),
      title: nm ? `Name “${nm}”` : "Name this new device",
      sub: [d.type_label && d.type_label !== "Unknown" ? d.type_label : null,
            d.vendor && d.vendor !== "—" && d.vendor !== nm ? d.vendor : null,
            d.ip, d.mac].filter(Boolean).join("  ·  "),
      when: timeAgo(d.first_seen),
      go: () => showTab("devices"),
    });
  }
  for (const a of (STATE.alerts || []).filter(a => !a.acknowledged).slice(0, 5)) {
    items.push({
      kind: "alert",
      sev: a.severity || "info",
      icon: SEV_ICON[a.severity] || SEV_ICON.info,
      title: a.title,
      sub: a.message,
      when: timeAgo(a.ts),
      go: () => showTab("activity"),
    });
  }
  // Severity first (critical → warning → info), then recency as given.
  const rank = { critical: 0, warning: 1, info: 2 };
  items.sort((a, b) => (rank[a.sev] ?? 3) - (rank[b.sev] ?? 3));

  if (!items.length) {
    list.innerHTML = `
      <div class="attention-clear">
        ${SEV_ICON.ok}
        <span>Nothing needs your attention. Every device has a name and there are no unread alerts.</span>
      </div>`;
    return;
  }
  list.innerHTML = items.slice(0, 6).map((it, i) => `
    <button class="attention-row" data-att="${i}">
      <span class="attention-glyph sev-${escHtml(it.sev)}">${it.icon}</span>
      <span class="attention-body">
        <span class="attention-title">${escHtml(it.title)}</span>
        <span class="attention-sub">${escHtml(it.sub)}</span>
      </span>
      <span class="attention-when">${escHtml(it.when)}</span>
    </button>`).join("");
  list.querySelectorAll("[data-att]").forEach(el =>
    el.addEventListener("click", () => items[Number(el.dataset.att)].go()));
}

// ── overview: glance strip ────────────────────────────────────────────────
function paintGlance() {
  const grid = $("#overview-summary");
  const devs = STATE.devices || [];
  const present = devs.filter(d => d.present !== false);
  const known   = present.filter(d => d.is_known && !d.me).length;
  const unknown = present.filter(d => !d.is_known && !d.me).length;
  const away    = devs.filter(d => d.present === false).length;
  const wan     = (STATE.wan_mappings || []).length;

  grid.innerHTML = [
    { n: present.length, l: "connected now" },
    { n: known,          l: "known devices" },
    { n: unknown,        l: "unknown", cls: unknown ? "is-warn" : "" },
    { n: away,           l: "recently away" },
    { n: wan,            l: "reachable from the internet", cls: wan ? "is-crit" : "" },
  ].map(c => `
    <div class="glance-cell ${c.cls || ""}">
      <span class="glance-num">${escHtml(c.n)}</span>
      <span class="glance-lbl">${escHtml(c.l)}</span>
    </div>`).join("");
}

// ── devices ───────────────────────────────────────────────────────────────
function deviceMatchesFilter(d) {
  const q = $("#dev-search").value.toLowerCase().trim();
  if (q) {
    const blob = `${d.ip} ${d.mac} ${d.hostname} ${d.vendor} ${d.known_name} ${d.fingerprint} ${d.type_label}`.toLowerCase();
    if (!blob.includes(q)) return false;
  }
  const typeFilter = $("#dev-type-filter").value;
  if (typeFilter && d.device_type !== typeFilter) return false;

  const kf = $("#dev-known-filter").value;
  if (kf === "known"        && !d.is_known) return false;
  if (kf === "unknown"      && (d.is_known || d.me)) return false;
  if (kf === "unidentified" && d.device_type !== "unknown") return false;
  return true;
}

let LIST_SORT = (() => {
  try {
    return JSON.parse(localStorage.getItem("ins.listSort") || "null")
      || { key: "ip", dir: "asc" };
  } catch { return { key: "ip", dir: "asc" }; }
})();

function setListSort(key) {
  if (LIST_SORT.key === key) {
    LIST_SORT.dir = LIST_SORT.dir === "asc" ? "desc" : "asc";
  } else {
    LIST_SORT = { key, dir: "asc" };
  }
  localStorage.setItem("ins.listSort", JSON.stringify(LIST_SORT));
  applyListSortIndicators();
  if (STATE) paintDevices();
}
function applyListSortIndicators() {
  $$(".dl-head .dl-sort").forEach(el => {
    const active = el.dataset.sort === LIST_SORT.key;
    el.classList.toggle("active", active);
    el.dataset.dir = active ? LIST_SORT.dir : "";
    el.setAttribute("aria-sort",
      active ? (LIST_SORT.dir === "asc" ? "ascending" : "descending") : "none");
  });
}
$$(".dl-head .dl-sort").forEach(el =>
  el.addEventListener("click", () => setListSort(el.dataset.sort)));
applyListSortIndicators();

function ipNum(s) {
  const parts = String(s || "").split(".").map(n => parseInt(n, 10));
  if (parts.length !== 4 || parts.some(isNaN)) return -1;
  return ((parts[0] << 24) >>> 0) + (parts[1] << 16) + (parts[2] << 8) + parts[3];
}
function sortKeyValue(d, key) {
  switch (key) {
    case "name":   return (bestName(d) || "￿").toLowerCase();
    case "ip":     return ipNum(d.ip);
    case "mac":    return (d.mac || "").toLowerCase();
    case "ports":  return (d.ports || []).length;
    case "bw":     return currentBps(d, "total");
    default:       return "";
  }
}
function sortedForList(devices) {
  const { key, dir } = LIST_SORT;
  const sign = dir === "desc" ? -1 : 1;
  return [...devices].sort((a, b) => {
    const av = sortKeyValue(a, key);
    const bv = sortKeyValue(b, key);
    if (av < bv) return -1 * sign;
    if (av > bv) return  1 * sign;
    return 0;
  });
}

// Bandwidth helpers — samples are [(ts, bytes_in, bytes_out), ...] per ~60s window.
function currentBps(d, dir) {
  const s = d.bw_samples;
  if (!Array.isArray(s) || !s.length) return 0;
  const last = s[s.length - 1];
  const bin  = last[1] / 60;
  const bout = last[2] / 60;
  if (dir === "in")  return bin;
  if (dir === "out") return bout;
  return bin + bout;
}
function fmtRate(bps) {
  if (!bps || bps < 1) return "0";
  const u = ["B/s", "KB/s", "MB/s", "GB/s"];
  let i = 0, v = bps;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return (v >= 100 ? v.toFixed(0) : v.toFixed(1)) + " " + u[i];
}
function bandwidthCell(d) {
  const samples = d.bw_samples || [];
  if (!samples.length) {
    return `<span class="dl-c dl-c-bw"><span class="bw-empty">—</span></span>`;
  }
  const inBps  = currentBps(d, "in");
  const outBps = currentBps(d, "out");
  const total  = inBps + outBps;
  const W = 56, H = 18;
  const slots = samples.slice(-30);
  const maxVal = Math.max(1, ...slots.map(s => Math.max(s[1], s[2])));
  const sx = i => (W * i) / Math.max(1, slots.length - 1);
  const sy = v => H - 1 - ((v / maxVal) * (H - 2));
  const path = (idx) => slots.map((s, i) =>
    `${i ? "L" : "M"}${sx(i).toFixed(1)} ${sy(s[idx]).toFixed(1)}`).join(" ");
  return `
    <span class="dl-c dl-c-bw" title="Down ${escHtml(fmtRate(inBps))} · up ${escHtml(fmtRate(outBps))} (last minute)">
      <svg class="bw-spark" viewBox="0 0 ${W} ${H}" preserveAspectRatio="none">
        <path class="in"  d="${escHtml(path(1))}"></path>
        <path class="out" d="${escHtml(path(2))}"></path>
      </svg>
      <span class="bw-rate">${escHtml(fmtRate(total))}</span>
    </span>`;
}

function paintDevices() {
  // Rebuild the type filter only when the option set changed and it's not in use.
  const sel = $("#dev-type-filter");
  const seenTypes = [...new Set((STATE.devices || []).map(d => d.device_type).filter(Boolean))].sort();
  const currentOpts = Array.from(sel.options).map(o => o.value).filter(Boolean).sort();
  if (currentOpts.join(",") !== seenTypes.join(",") && document.activeElement !== sel) {
    const prev = sel.value;
    sel.innerHTML = `<option value="">All types</option>` +
      seenTypes.map(t => {
        const ex = STATE.devices.find(d => d.device_type === t);
        return `<option value="${escHtml(t)}">${escHtml(ex?.type_label || t)}</option>`;
      }).join("");
    if (seenTypes.includes(prev)) sel.value = prev;
  }

  const body = $("#device-list-body");
  const visible = (STATE.devices || []).filter(deviceMatchesFilter);
  if (!visible.length) {
    body.innerHTML = (STATE.devices || []).length
      ? `<div class="empty">No devices match the current filter.</div>`
      : `<div class="empty">No devices yet. The first scan is on its way.</div>`;
    return;
  }
  body.innerHTML = sortedForList(visible).map(deviceRow).join("");
  body.querySelectorAll("[data-action]").forEach(el => {
    el.addEventListener("click", (e) => { e.stopPropagation(); onDeviceAction(e); });
  });
  body.querySelectorAll("[data-row-mac]").forEach(row => {
    row.addEventListener("click", () => openDeviceStory(row.dataset.rowMac));
    row.addEventListener("keydown", (e) => {
      if ((e.key === "Enter" || e.key === " ") &&
          !e.target.closest("[data-action], button, input, select")) {
        e.preventDefault();
        openDeviceStory(row.dataset.rowMac);
      }
    });
  });
}

function deviceRow(d) {
  const identifying = !d.me && !d.is_known &&
    (d.device_type === "unknown" || (d.type_confidence ?? 0) < 0.3);
  const dotKlass = d.me ? "s-me"
                 : d.is_known ? "s-known"
                 : identifying ? "s-identifying"
                 : "s-unknown";
  const name = bestName(d);
  const away = d.present === false;
  const subBits = [];
  if (d.type_label && d.type_label !== "Unknown") subBits.push(d.type_label);
  else if (identifying) subBits.push("Identifying…");
  if (d.vendor && d.vendor !== "—" && d.vendor !== name) subBits.push(d.vendor);
  if (away) subBits.push(`away · last seen ${timeAgo(d.last_seen)}`);

  const ports = (d.ports || []).slice(0, 5).map(p =>
    `<span class="port-chip${RISKY_PORTS.has(p) ? " risky" : ""}">${p}</span>`).join("");
  const extraPorts = Math.max(0, (d.ports || []).length - 5);

  const action = d.me ? `<span class="dl-self">you</span>`
    : d.is_known
      ? `<button class="btn btn-ghost" data-action="unknown" data-mac="${escHtml(d.mac)}">Forget</button>`
      : `<button class="btn" data-action="known" data-mac="${escHtml(d.mac)}" data-name="${escHtml(name)}">Name</button>`;

  return `
    <div class="dl-row${away ? " is-away" : ""}" data-row-mac="${escHtml(d.mac)}" tabindex="0" role="button"
         aria-label="View details for ${escHtml(name || d.ip || "device")}">
      <span class="dl-c"><span class="dc-status ${dotKlass}"></span></span>
      <span class="dl-c dl-c-icon">${devIcon(d.device_type)}</span>
      <span class="dl-c dl-c-name">
        <span class="dev-name${name ? "" : " unnamed"}">${escHtml(name || "unnamed device")}</span>
        ${subBits.length ? `<span class="dev-sub">${escHtml(subBits.join("  ·  "))}</span>` : ""}
      </span>
      <span class="dl-c dl-c-ip">${escHtml(d.ip || "—")}</span>
      <span class="dl-c dl-c-mac">${escHtml(d.mac || "—")}</span>
      ${bandwidthCell(d)}
      <span class="dl-c dl-c-ports">${ports}${extraPorts ? `<span class="dl-ports-more">+${extraPorts}</span>` : ""}</span>
      <span class="dl-c dl-c-actions">${action}</span>
    </div>`;
}

async function onDeviceAction(e) {
  const el = e.currentTarget;
  const mac = el.dataset.mac;
  const action = el.dataset.action;
  if (action === "known") {
    const name = prompt("Name for this device:", el.dataset.name || "");
    if (name === null) return;
    await api("/api/known/add", { mac, name });
  } else if (action === "unknown") {
    await api("/api/known/remove", { mac });
  } else if (action === "wol") {
    await api("/api/wol", { mac });
  } else if (action === "probe") {
    const newState = el.dataset.state !== "1";
    await api("/api/devices/no_probe", { mac, no_probe: newState });
  }
  refresh();
}

["#dev-search", "#dev-type-filter", "#dev-known-filter"].forEach(s =>
  document.querySelector(s).addEventListener("input", () => { if (STATE) paintDevices(); }));

// ── triage strip ──────────────────────────────────────────────────────────
function paintTriage() {
  const strip = $("#triage-strip");
  const list  = $("#triage-list");
  // Don't rebuild while the user is typing a name.
  if (document.activeElement && document.activeElement.matches("#triage-list .triage-name")) return;
  const items = STATE.triage || [];
  strip.hidden = !items.length;
  if (!items.length) { list.innerHTML = ""; return; }

  $("#triage-heading").textContent =
    `${items.length} new device${items.length === 1 ? "" : "s"} to name`;

  list.innerHTML = items.map(d => {
    const suggested = bestName(d);
    return `
      <div class="triage-row" data-mac="${escHtml(d.mac)}">
        <span class="triage-icon">${devIcon(d.device_type)}</span>
        <span class="triage-info">
          <span class="triage-title">${escHtml(d.type_label || "Unknown device")}<span class="triage-vendor">${escHtml(d.vendor && d.vendor !== "—" ? d.vendor : "")}</span></span>
          <span class="triage-sub">${escHtml(d.ip)} · ${escHtml(d.mac)} · first seen ${escHtml(timeAgo(d.first_seen || 0))}</span>
          ${d.fingerprint ? `<span class="triage-fp">${escHtml(d.fingerprint)}</span>` : ""}
        </span>
        <input type="text" class="triage-name" aria-label="Device name" placeholder="Name this device" value="${escHtml(suggested)}">
        <button class="btn" data-triage-act="known">Save</button>
        <button class="btn btn-ghost" data-triage-act="block" title="Stop actively probing this device">Ignore</button>
      </div>`;
  }).join("");

  list.querySelectorAll("[data-triage-act]").forEach(b => {
    b.addEventListener("click", async () => {
      const row = b.closest(".triage-row");
      const mac = row.dataset.mac;
      if (b.dataset.triageAct === "known") {
        const name = row.querySelector(".triage-name").value.trim();
        await api("/api/known/add", { mac, name });
      } else {
        await api("/api/devices/no_probe", { mac, no_probe: true });
      }
      refresh();
    });
  });
}

$("#triage-bulk-known").addEventListener("click", async () => {
  const rows = $$("#triage-list .triage-row");
  const entries = rows.map(r => ({
    mac:  r.dataset.mac,
    name: r.querySelector(".triage-name").value.trim(),
  })).filter(e => e.mac);
  if (!entries.length) return;
  if (!confirm(`Mark ${entries.length} device${entries.length === 1 ? "" : "s"} as known?`)) return;
  await api("/api/triage/bulk_known", { entries });
  refresh();
});

// ── alerts ────────────────────────────────────────────────────────────────
function paintAlerts() {
  const list = $("#alerts-list");
  const alerts = STATE.alerts || [];
  if (!alerts.length) {
    list.innerHTML = `<div class="empty">Nothing has needed your attention yet. New devices and risky ports will show up here.</div>`;
    return;
  }
  list.innerHTML = alerts.map(alertRow).join("");
  wireAlertActions(list);
}

function alertRow(a) {
  const sev  = a.severity || "info";
  const icon = SEV_ICON[sev] || SEV_ICON.info;
  return `
    <div class="alert-row sev-${escHtml(sev)} ${a.acknowledged ? "is-ack" : ""}" data-alert-kind="${escHtml(a.kind)}">
      <div class="alert-sev">${icon}</div>
      <div class="alert-body">
        <div class="alert-title">${escHtml(a.title)}</div>
        <div class="alert-msg">${escHtml(a.message)}</div>
        <div class="alert-time">${escHtml(timeAgo(a.ts))} · ${escHtml(a.kind)}</div>
      </div>
      <div class="alert-actions">
        <button class="btn btn-ghost" data-explain="${escHtml(a.kind)}">What does this mean?</button>
        ${a.acknowledged ? "" : `<button class="btn" data-ack="${a.id}">Mark read</button>`}
      </div>
    </div>`;
}

function wireAlertActions(scope) {
  scope.querySelectorAll("[data-ack]").forEach(el => {
    el.addEventListener("click", async () => {
      await api("/api/alerts/ack", { id: Number(el.dataset.ack) });
      refresh();
    });
  });
  scope.querySelectorAll("[data-explain]").forEach(el => {
    el.addEventListener("click", () => openExplainer(el.dataset.explain));
  });
}

$("#ack-all").addEventListener("click", async () => {
  await api("/api/alerts/ack_all", {});
  refresh();
});

// ── alert explainer drawer ────────────────────────────────────────────────
function openExplainer(kind) {
  const help = ALERT_HELP.find(([prefix]) => kind.startsWith(prefix))?.[1];
  if (!help) return;
  _lastFocus = document.activeElement;
  $("#drawer-title").textContent = help.title;
  $("#drawer-body").innerHTML = `
    <h3>Why this matters</h3>
    <p>${escHtml(help.why)}</p>
    <h3>What to do</h3>
    <p>${escHtml(help.do)}</p>
  `;
  $("#alert-drawer").hidden = false;
  $("#drawer-scrim").hidden = false;
  _syncModalState();
  $("#drawer-close").focus();
}
function closeExplainer() {
  $("#alert-drawer").hidden = true;
  $("#drawer-scrim").hidden = true;
  _syncModalState();
  _restoreFocus();
}
$("#drawer-close").addEventListener("click", closeExplainer);
$("#drawer-scrim").addEventListener("click", closeExplainer);

// ── history chart ─────────────────────────────────────────────────────────
function drawHistory() {
  const canvas = $("#history-chart");
  if (!canvas || CURRENT_TAB !== "activity") return;
  const css = (name, fb) =>
    (getComputedStyle(document.documentElement).getPropertyValue(name).trim() || fb);
  const accent = css("--accent", "#7fc7cf");
  const grid   = css("--line", "rgba(255,255,255,.07)");
  const labelC = css("--text-3", "#7c8698");
  const mono   = "10px 'Geist Mono', ui-monospace, monospace";
  const dpr = window.devicePixelRatio || 1;
  const w = canvas.clientWidth, h = canvas.clientHeight;
  if (!w || !h) return;
  canvas.width = w * dpr; canvas.height = h * dpr;
  const ctx = canvas.getContext("2d");
  ctx.scale(dpr, dpr);
  ctx.clearRect(0, 0, w, h);
  if (!HISTORY.length) {
    ctx.fillStyle = labelC;
    ctx.font = mono;
    ctx.textAlign = "center";
    ctx.fillText("No scan history yet", w / 2, h / 2);
    return;
  }
  const max = Math.max(...HISTORY.map(p => p.count), 1);
  const padX = 40, padY = 18;
  const innerW = w - padX - 16, innerH = h - padY * 2;
  const xs = (i) => padX + (i / (HISTORY.length - 1 || 1)) * innerW;
  const ys = (v) => padY + innerH - (v / max) * innerH;

  ctx.strokeStyle = grid;
  ctx.lineWidth = 1;
  for (let i = 0; i <= 4; i++) {
    const y = padY + (innerH * i) / 4;
    ctx.beginPath(); ctx.moveTo(padX, y); ctx.lineTo(w - 16, y); ctx.stroke();
  }

  ctx.strokeStyle = accent;
  ctx.lineWidth = 1.5;
  ctx.lineJoin = "round";
  ctx.beginPath();
  HISTORY.forEach((p, i) => {
    if (i === 0) ctx.moveTo(xs(i), ys(p.count));
    else ctx.lineTo(xs(i), ys(p.count));
  });
  ctx.stroke();

  ctx.lineTo(xs(HISTORY.length - 1), padY + innerH);
  ctx.lineTo(xs(0), padY + innerH);
  ctx.closePath();
  ctx.globalAlpha = 0.07;
  ctx.fillStyle = accent;
  ctx.fill();
  ctx.globalAlpha = 1;

  ctx.fillStyle = labelC;
  ctx.font = mono;
  ctx.textAlign = "right";
  for (let i = 0; i <= 4; i++) {
    const v = Math.round(max - (max * i) / 4);
    ctx.fillText(String(v), padX - 9, padY + (innerH * i) / 4 + 3);
  }
}

let _historyResizeTimer = null;
window.addEventListener("resize", () => {
  clearTimeout(_historyResizeTimer);
  _historyResizeTimer = setTimeout(() => {
    if (CURRENT_TAB === "activity") drawHistory();
  }, 150);
});

// ── device story drawer ───────────────────────────────────────────────────
async function openDeviceStory(mac) {
  const opener = document.activeElement;
  try {
    const story = await fetch(`/api/device/${encodeURIComponent(mac)}`).then(r => r.json());
    if (!story || story.error) return;
    _lastFocus = opener;
    const d = story.device || {};
    const fpHints = d.fingerprint || {};
    const fpText = typeof fpHints === "string" ? fpHints
      : (fpHints.mdns || fpHints.ssdp || fpHints.smb || fpHints.dhcp_hostname || "");
    const name = story.known_name || fpText ||
      (d.hostname && d.hostname !== "—" ? d.hostname : "") || d.vendor || mac;
    $("#device-drawer-title").textContent = name;

    const sightings = (story.sightings || []).slice(0, 30);
    const sightingsHtml = sightings.length
      ? sightings.map(s => `
          <div class="dstory-row">
            <span class="dstory-ts">${escHtml(new Date(s.ts * 1000).toLocaleString())}</span>
            <span class="dstory-ip">${escHtml(s.ip || "—")}</span>
            <span class="dstory-lat">${s.latency_ms != null ? escHtml(s.latency_ms) + " ms" : ""}</span>
          </div>`).join("")
      : `<div class="empty">No sightings recorded yet.</div>`;

    const alerts = (story.alerts || []).slice(0, 20);
    const alertsHtml = alerts.length
      ? alerts.map(a => {
          const sev = a.severity || "info";
          return `
            <div class="dstory-alert sev-${escHtml(sev)}">
              <div class="dstory-alert-head"><span class="dstory-alert-icon">${SEV_ICON[sev] || SEV_ICON.info}</span><strong>${escHtml(a.title)}</strong></div>
              <div class="dstory-alert-msg">${escHtml(a.message)}</div>
              <div class="dstory-alert-ts">${escHtml(new Date(a.ts * 1000).toLocaleString())}${a.acknowledged ? " · read" : ""}</div>
            </div>`;
        }).join("")
      : `<div class="empty">No alerts triggered by this device.</div>`;

    const ports = (d.ports || []).length
      ? (d.ports || []).map(p => `<span class="port-chip${RISKY_PORTS.has(p) ? " risky" : ""}">${p}</span>`).join("")
      : `<span class="empty-inline">No open ports observed.</span>`;

    const wan = (story.wan_exposed || []).length
      ? (story.wan_exposed || []).map(m => `<div class="dstory-wan">${SEV_ICON.warning}<span>External port ${escHtml(m.external_port)}/${escHtml(m.protocol)} is forwarded to this device (port ${escHtml(m.internal_port)})</span></div>`).join("")
      : "";

    const routerKind = (STATE.settings && STATE.settings.router_kind) || "none";
    const isMe = !!d.me;
    const routerButtons = (routerKind === "none" || isMe) ? "" : `
      <div class="dstory-router-actions">
        <button class="btn btn-danger" id="router-block-mac" data-mac="${escHtml(d.mac || mac)}">Block on router</button>
        <button class="btn" id="router-unblock-mac" data-mac="${escHtml(d.mac || mac)}">Unblock</button>
        <span class="dstory-router-status" id="dstory-router-status"></span>
      </div>`;

    const probeBtn = isMe ? "" : `
      <div class="dstory-router-actions">
        <button class="btn btn-ghost" data-action="probe" data-mac="${escHtml(d.mac || mac)}" data-state="${d.no_probe ? "1" : "0"}">
          ${d.no_probe ? "Resume probing" : "Don't probe this device"}
        </button>
        <button class="btn btn-ghost" data-action="wol" data-mac="${escHtml(d.mac || mac)}">Wake on LAN</button>
      </div>`;

    $("#device-drawer-body").innerHTML = `
      ${routerButtons}
      ${wan}
      <h3>Identity</h3>
      <dl class="dstory-meta">
        <dt>IP</dt><dd class="mono">${escHtml(d.ip || "—")}</dd>
        <dt>MAC</dt><dd class="mono">${escHtml(d.mac || mac)}</dd>
        <dt>Vendor</dt><dd>${escHtml(d.vendor || "—")}</dd>
        <dt>Type</dt><dd>${escHtml(d.device_type || "unknown")} <span class="mono">(${Math.round((d.type_confidence || 0) * 100)}% confident)</span></dd>
        <dt>First seen</dt><dd>${escHtml(d.first_seen ? new Date(d.first_seen * 1000).toLocaleString() : "—")}</dd>
        <dt>Last seen</dt><dd>${escHtml(d.last_seen ? new Date(d.last_seen * 1000).toLocaleString() : "—")}</dd>
        <dt>Times seen</dt><dd class="mono">${escHtml(d.seen_count || 0)}</dd>
        <dt>Known</dt><dd>${story.is_known ? `<strong>${escHtml(story.known_name || "yes")}</strong>` : "not yet"}</dd>
      </dl>
      <h3>Open ports</h3>
      <div class="dc-ports">${ports}</div>
      <h3>Recent sightings</h3>
      <div class="dstory-list">${sightingsHtml}</div>
      ${renderBandwidthBlock(story.bandwidth || [])}
      ${renderDnsBlock(story.dns || [])}
      <h3>Alerts from this device</h3>
      <div class="dstory-list">${alertsHtml}</div>
      ${probeBtn}
    `;

    $("#device-drawer").hidden = false;
    $("#drawer-scrim").hidden = false;
    _syncModalState();
    $("#device-drawer-close").focus();

    $("#device-drawer-body").querySelectorAll("[data-action]").forEach(el =>
      el.addEventListener("click", (e) => { onDeviceAction(e); closeDeviceDrawer(); }));

    const wireRouter = (sel, path, verb) =>
      document.getElementById(sel)?.addEventListener("click", async (e) => {
        const btn = e.currentTarget;
        const status = $("#dstory-router-status");
        const macAddr = btn.dataset.mac;
        if (verb === "block" && !confirm(`Block ${macAddr} on your router? It will be kicked off the WiFi immediately.`)) return;
        status.textContent = `${verb}ing…`;
        const r = await api(path, { mac: macAddr });
        status.textContent = r.ok ? `${verb}ed ✓` : `${verb} failed: ${r.error || "unknown"}`;
      });
    wireRouter("router-block-mac",   "/api/router/block",   "block");
    wireRouter("router-unblock-mac", "/api/router/unblock", "unblock");
  } catch (e) { /* swallow */ }
}

function fmtBytes(n) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)} MB`;
  return `${(n / 1024 / 1024 / 1024).toFixed(2)} GB`;
}

function renderBandwidthBlock(samples) {
  if (!samples.length) {
    return `<h3>Bandwidth (last hour)</h3>
            <div class="empty">No data — bandwidth needs the passive sniffer (Settings → Passive sniffer).</div>`;
  }
  const totalIn  = samples.reduce((s, r) => s + (r.bytes_in  || 0), 0);
  const totalOut = samples.reduce((s, r) => s + (r.bytes_out || 0), 0);
  const max = Math.max(...samples.map(r => Math.max(r.bytes_in, r.bytes_out)), 1);
  const bars = samples.slice(-60).map(r => {
    const inH  = Math.max(2, Math.round((r.bytes_in  / max) * 40));
    const outH = Math.max(2, Math.round((r.bytes_out / max) * 40));
    return `<span class="bw-pair" title="${new Date(r.ts * 1000).toLocaleTimeString()}: down ${fmtBytes(r.bytes_in)} / up ${fmtBytes(r.bytes_out)}">
              <span class="bw-bar bw-in"  style="height:${inH}px"></span>
              <span class="bw-bar bw-out" style="height:${outH}px"></span>
            </span>`;
  }).join("");
  return `<h3>Bandwidth (last hour)</h3>
          <div class="bw-summary">Down <strong>${fmtBytes(totalIn)}</strong> · Up <strong>${fmtBytes(totalOut)}</strong></div>
          <div class="bw-chart">${bars}</div>`;
}

function renderDnsBlock(queries) {
  if (!queries.length) {
    return `<h3>DNS lookups</h3>
            <div class="empty">No DNS logged for this device. Needs the passive sniffer.</div>`;
  }
  const rows = queries.slice(0, 25).map(q => `
    <div class="dstory-row">
      <span class="dstory-ts">${escHtml(new Date(q.ts * 1000).toLocaleString())}</span>
      <span class="dstory-ip">${escHtml(q.qname)}</span>
    </div>`).join("");
  return `<h3>DNS lookups</h3>
          <div class="dstory-list">${rows}</div>`;
}

function closeDeviceDrawer() {
  $("#device-drawer").hidden = true;
  if ($("#alert-drawer").hidden) $("#drawer-scrim").hidden = true;
  _syncModalState();
  _restoreFocus();
}
$("#device-drawer-close").addEventListener("click", closeDeviceDrawer);
$("#drawer-scrim").addEventListener("click", closeDeviceDrawer);

// ── onboarding tour ───────────────────────────────────────────────────────
const TOUR_STEPS = [
  {
    title: "Welcome to Inglorious Network Scanner",
    body:  "INS quietly watches everything on your WiFi and tells you, in plain English, when something deserves attention. Two things worth knowing before you dive in.",
  },
  {
    title: "The Overview answers one question",
    body:  "Is my network okay? The big statement at the top tells you outright, and everything that needs you is collected right beneath it, most serious first.",
  },
  {
    title: "Name your devices once",
    body:  "The Devices tab lists everything connected. Spend two minutes naming what you recognize (your phone, the TV, the printer) so INS only ever bothers you about genuine strangers.",
  },
];
let TOUR_INDEX = 0;
function showOnboardingIfNeeded() {
  if (!STATE || !STATE.settings) return;
  if (STATE.settings.first_run_done) return;
  if (!$("#onboarding").hidden) return;
  TOUR_INDEX = 0;
  renderTourStep();
  $("#onboarding").hidden = false;
  _syncModalState();
  $("#onboarding-next").focus();
}
function renderTourStep() {
  const step = TOUR_STEPS[TOUR_INDEX];
  $("#onboarding-step").innerHTML =
    `<h2>${escHtml(step.title)}</h2><p>${escHtml(step.body)}</p>`;
  $("#onboarding-pips").innerHTML = TOUR_STEPS
    .map((_, i) => `<span class="pip ${i === TOUR_INDEX ? "active" : ""}"></span>`).join("");
  $("#onboarding-next").textContent =
    TOUR_INDEX === TOUR_STEPS.length - 1 ? "Got it" : "Next";
}
async function finishTour() {
  $("#onboarding").hidden = true;
  _syncModalState();
  await api("/api/settings/save", { first_run_done: "1" });
  refresh();
}
$("#onboarding-next").addEventListener("click", () => {
  if (TOUR_INDEX < TOUR_STEPS.length - 1) {
    TOUR_INDEX++;
    renderTourStep();
  } else {
    finishTour();
  }
});
$("#onboarding-skip").addEventListener("click", finishTour);

// ── settings: webhooks ────────────────────────────────────────────────────
function paintWebhooks() {
  const list = $("#webhook-list");
  const hooks = STATE.webhooks || [];
  if (!hooks.length) {
    list.innerHTML = `<div class="empty">No webhooks configured.</div>`;
    return;
  }
  list.innerHTML = hooks.map(h => `
    <div class="wh-row ${h.enabled ? "" : "disabled"}">
      <span class="wh-label">${escHtml(h.label || "(no label)")}</span>
      <span class="wh-url">${escHtml(h.url)}</span>
      <span class="wh-sev">${escHtml(h.min_severity)}</span>
      <button class="btn" data-wh-toggle="${h.id}" data-wh-enabled="${h.enabled}">${h.enabled ? "Disable" : "Enable"}</button>
      <button class="btn btn-danger" data-wh-remove="${h.id}">Delete</button>
    </div>
  `).join("");
  list.querySelectorAll("[data-wh-toggle]").forEach(b =>
    b.addEventListener("click", async () => {
      await api("/api/webhooks/toggle",
        { id: Number(b.dataset.whToggle), enabled: b.dataset.whEnabled !== "1" });
      refresh();
    }));
  list.querySelectorAll("[data-wh-remove]").forEach(b =>
    b.addEventListener("click", async () => {
      if (!confirm("Delete this webhook?")) return;
      await api("/api/webhooks/remove", { id: Number(b.dataset.whRemove) });
      refresh();
    }));
}

$("#wh-add").addEventListener("click", async () => {
  const url = $("#wh-url").value.trim();
  if (!url) return;
  const label = $("#wh-label").value.trim();
  const min_severity = $("#wh-severity").value;
  await api("/api/webhooks/add", { url, label, min_severity });
  $("#wh-label").value = ""; $("#wh-url").value = "";
  refresh();
});

// ── settings: hook script ─────────────────────────────────────────────────
function paintHook() {
  const ta = $("#hook-script");
  if (document.activeElement !== ta) {
    ta.value = STATE.hook || "";
  }
}
$("#hook-save").addEventListener("click", async () => {
  await api("/api/hook", { script: $("#hook-script").value });
});

// ── settings: voice / shortcuts / keep-alive / sniffer ────────────────────
function paintSettings() {
  const s = (STATE.settings || {});
  const voiceEl = $("#setting-voice");
  const newEl   = $("#setting-shortcut-new");
  const altEl   = $("#setting-shortcut-alert");
  const kaEl    = $("#setting-keep-alive");
  if (voiceEl && document.activeElement !== voiceEl) voiceEl.checked = !!s.voice_enabled;
  if (newEl   && document.activeElement !== newEl)   newEl.value     = s.shortcut_on_new_device || "";
  if (altEl   && document.activeElement !== altEl)   altEl.value     = s.shortcut_on_alert || "";
  if (kaEl    && document.activeElement !== kaEl)    kaEl.checked    = !!s.keep_alive;
  const snEl = $("#sniffer-status");
  if (snEl) {
    const sn = STATE.sniffer || {};
    if (sn.running) {
      snEl.textContent = `Running: ${(sn.packets || 0).toLocaleString()} packets observed`;
    } else if (sn.reason) {
      snEl.textContent = `Not active: ${sn.reason}`;
    } else {
      snEl.textContent = "Not active. Run tools/enable_sniffer.sh with sudo, then restart INS.";
    }
  }
  paintRouterSettings();
}

$("#keep-alive-save")?.addEventListener("click", async () => {
  const status = $("#keep-alive-status");
  status.textContent = "Applying…";
  // Applying keep-alive reloads the LaunchAgent, which briefly restarts INS —
  // a dropped socket here means "restarting", not failure.
  try {
    const r = await fetch("/api/settings/save", {
      method: "POST", headers: {"Content-Type": "application/json"},
      body: JSON.stringify({ keep_alive: $("#setting-keep-alive").checked ? "1" : "0" }),
    }).then(r => r.json());
    status.textContent = r.ok ? "Applied. INS is restarting…" : `Failed: ${r.error || "unknown"}`;
  } catch {
    status.textContent = "Applied. INS is restarting…";
  }
  setTimeout(() => { status.textContent = ""; }, 4000);
});

$("#settings-save")?.addEventListener("click", async () => {
  const status = $("#settings-status");
  status.textContent = "Saving…";
  await api("/api/settings/save", {
    voice_enabled:          $("#setting-voice").checked ? "1" : "0",
    shortcut_on_new_device: $("#setting-shortcut-new").value.trim(),
    shortcut_on_alert:      $("#setting-shortcut-alert").value.trim(),
  });
  status.textContent = "Saved";
  setTimeout(() => { status.textContent = ""; }, 1500);
  refresh();
});

// ── settings: remote access ───────────────────────────────────────────────
async function loadRemoteAccess() {
  if (!document.getElementById("setting-remote")) return;
  try {
    const r = await fetch("/api/remote");
    if (r.ok) renderRemoteAccess(await r.json());
  } catch { /* ignore */ }
}
function renderRemoteAccess(info) {
  if (!info) return;
  const toggle = $("#setting-remote");
  if (!toggle) return;
  if (document.activeElement !== toggle) toggle.checked = !!info.enabled;
  const details = $("#remote-details");
  if (details) details.hidden = !info.enabled;
  const urlEl = $("#remote-url");   if (urlEl) urlEl.textContent = info.url || "—";
  const tokEl = $("#remote-token"); if (tokEl) tokEl.textContent = info.token || "—";
}
document.getElementById("setting-remote")?.addEventListener("change", async (e) => {
  const status = $("#remote-status");
  const enabled = e.currentTarget.checked;
  status.textContent = enabled ? "Enabling…" : "Disabling…";
  try {
    const info = await api("/api/remote", { enabled });
    renderRemoteAccess(info);
    status.textContent = enabled
      ? `On: reachable at ${info.url || "your LAN IP"}`
      : "Off: this Mac only.";
  } catch {
    status.textContent = "Couldn't apply. Try again.";
  }
  setTimeout(() => { status.textContent = ""; }, 5000);
});
document.getElementById("remote-copy")?.addEventListener("click", async () => {
  const token = $("#remote-token")?.textContent || "";
  const status = $("#remote-status");
  try { await navigator.clipboard.writeText(token); status.textContent = "Token copied."; }
  catch { status.textContent = "Copy failed. Select the token and copy manually."; }
  setTimeout(() => { status.textContent = ""; }, 3000);
});
document.getElementById("remote-regen")?.addEventListener("click", async () => {
  if (!confirm("Regenerate the token? Any device using the current one is disconnected immediately.")) return;
  const status = $("#remote-status");
  status.textContent = "Regenerating…";
  try {
    renderRemoteAccess(await api("/api/remote/regenerate", {}));
    status.textContent = "New token generated.";
  } catch { status.textContent = "Failed. Try again."; }
  setTimeout(() => { status.textContent = ""; }, 3000);
});

// ── settings: router ──────────────────────────────────────────────────────
function paintRouterSettings() {
  const s = (STATE.settings || {});
  const kind = $("#router-kind");
  if (kind && document.activeElement !== kind) kind.value = s.router_kind || "none";
  const fields = [
    ["#router-host", s.router_host], ["#router-user", s.router_user],
    ["#router-site", s.router_site], ["#router-ssh-port", s.router_ssh_port],
    ["#router-iface", s.router_iface],
  ];
  for (const [sel, val] of fields) {
    const el = document.querySelector(sel);
    if (el && document.activeElement !== el) el.value = val ?? "";
  }
  const vtls = $("#router-verify-tls");
  if (vtls && document.activeElement !== vtls) vtls.checked = !!s.router_verify_tls;
  applyRouterKindVisibility(s.router_kind || "none");
}
function applyRouterKindVisibility(k) {
  $$("[data-router-unifi]").forEach(el => el.hidden = (k !== "unifi"));
  $$("[data-router-openwrt]").forEach(el => el.hidden = (k !== "openwrt"));
}
$("#router-kind")?.addEventListener("change", () =>
  applyRouterKindVisibility($("#router-kind").value));
$("#router-save")?.addEventListener("click", async () => {
  const status = $("#router-status");
  status.textContent = "Saving…";
  const body = {
    router_kind:       $("#router-kind").value,
    router_host:       $("#router-host").value.trim(),
    router_user:       $("#router-user").value.trim(),
    router_site:       $("#router-site").value.trim() || "default",
    router_ssh_port:   $("#router-ssh-port").value.trim() || "22",
    router_iface:      $("#router-iface").value.trim() || "0",
    router_verify_tls: $("#router-verify-tls").checked ? "1" : "0",
  };
  const pwd = $("#router-pass").value;
  if (pwd) body.router_pass = pwd;
  await api("/api/settings/save", body);
  $("#router-pass").value = "";
  status.textContent = "Saved";
  setTimeout(() => { status.textContent = ""; }, 1500);
  refresh();
});
$("#router-test")?.addEventListener("click", async () => {
  const status = $("#router-status");
  status.textContent = "Testing…";
  const r = await fetch("/api/router/test", {method: "POST", headers: {"Content-Type": "application/json"}, body: "{}"}).then(r => r.json());
  status.textContent = r.ok ? `Connected: ${r.message}` : `Failed: ${r.message}`;
});

// ── SSE live updates ──────────────────────────────────────────────────────
let SSE_STATE = "connecting";   // "live" | "offline" | "polling"

function startSSE() {
  if (typeof EventSource === "undefined") { SSE_STATE = "polling"; updateLivePill(); return; }
  try {
    const es = new EventSource("/api/stream");
    const onEvent = () => refreshSoon();
    es.addEventListener("scan.completed", onEvent);
    es.addEventListener("alert.raised",   onEvent);
    es.addEventListener("device.joined",  onEvent);
    es.addEventListener("device.left",    onEvent);
    es.addEventListener("device.ports_changed", onEvent);
    es.addEventListener("device.vendor_changed", onEvent);
    es.onopen = () => { SSE_STATE = "live"; updateLivePill(); };
    es.onerror = () => {
      if (es.readyState === EventSource.CLOSED) { SSE_STATE = "offline"; updateLivePill(); }
    };
  } catch (e) { SSE_STATE = "polling"; updateLivePill(); }
}

function updateLivePill() {
  const pill = $(".live-pill");
  if (!pill) return;
  let cls = "", label = "live";
  const epoch = STATE && STATE.last_scan_epoch;
  const err   = STATE && STATE.last_scan_error;
  if (err && (!epoch || err >= epoch)) {
    cls = "is-offline"; label = "scan error";
  } else if (SSE_STATE === "offline") {
    cls = "is-offline"; label = "offline";
  } else if (SSE_STATE === "polling") {
    cls = "is-stale"; label = "polling";
  } else if (epoch) {
    const age = Date.now() / 1000 - epoch;
    if (age > 120) { cls = "is-stale"; label = "stale"; }
  }
  pill.classList.toggle("is-stale",   cls === "is-stale");
  pill.classList.toggle("is-offline", cls === "is-offline");
  const lbl = pill.querySelector(".live-label");
  if (lbl) lbl.textContent = label;
}

// ── Wi-Fi neighbor survey ─────────────────────────────────────────────────
function rssiKlass(r) {
  if (r >= -55) return "strong";
  if (r >= -75) return "";
  return "bad";
}
function renderWifiResults(neighbors) {
  const list = $("#wifi-list");
  if (!neighbors || !neighbors.length) {
    list.innerHTML = `<div class="empty">No nearby networks found.</div>`;
    $("#wifi-channels").innerHTML = "";
    return;
  }
  const rows = neighbors.map(n => `
    <div class="wifi-row${n.is_current ? " current" : ""}">
      <span class="wifi-ssid">${escHtml(n.ssid || "(hidden)")}${n.is_current ? '<span class="you">connected</span>' : ""}</span>
      <span class="wifi-bssid">${escHtml(n.bssid || "—")}</span>
      <span class="wifi-band">${escHtml(n.band || "—")}</span>
      <span class="wifi-ch">${n.channel || "—"}</span>
      <span class="wifi-rssi ${rssiKlass(n.rssi)}">${n.rssi} dBm</span>
      <span class="wifi-sec">${escHtml(n.security || "—")}</span>
    </div>`).join("");
  list.innerHTML = `
    <div class="wh-head">
      <span>Network</span><span>BSSID</span><span>Band</span><span>Ch</span><span>Signal</span><span>Security</span>
    </div>${rows}`;
  const bands = { "2.4 GHz": [1,2,3,4,5,6,7,8,9,10,11,12,13],
                  "5 GHz":   [36,40,44,48,52,56,60,64,100,104,108,112,116,120,124,128,132,136,140,149,153,157,161,165] };
  const channels = $("#wifi-channels");
  channels.innerHTML = Object.entries(bands).map(([band, chans]) => {
    const occ = {};
    neighbors.filter(n => n.band === band).forEach(n => {
      if (!occ[n.channel] || n.rssi > occ[n.channel]) occ[n.channel] = n.rssi;
    });
    const bars = chans.map(ch => {
      const r = occ[ch];
      const h = r != null ? Math.max(8, Math.min(64, 68 + r)) : 5;
      const cls = r == null ? "empty" : (neighbors.some(n => n.channel === ch && n.is_current) ? "active" : "");
      return `<div class="wifi-bar ${cls}" style="height:${h}px" title="ch ${ch}${r != null ? ` · best ${r} dBm` : " · idle"}"><span class="ch-label">${ch}</span></div>`;
    }).join("");
    return `<div><h3>${band}</h3><div class="wifi-bars">${bars}</div></div>`;
  }).join("");
}

async function runWifiScan() {
  const btn = $("#wifi-scan"), status = $("#wifi-status");
  if (!btn) return;
  btn.disabled = true;
  status.textContent = "Scanning… (3–10 s)";
  try {
    const r = await fetch("/api/wifi/scan", {
      method: "POST", headers: {"Content-Type":"application/json"}, body: "{}",
    }).then(r => r.json());
    if (r.error) { status.textContent = `Error: ${r.error}`; return; }
    renderWifiResults(r.neighbors || []);
    status.textContent = `${(r.neighbors || []).length} networks · ${new Date().toLocaleTimeString()}`;
  } catch (e) {
    status.textContent = `Error: ${e.message || e}`;
  } finally {
    btn.disabled = false;
  }
}
document.getElementById("wifi-scan")?.addEventListener("click", runWifiScan);

// ── header rescan ─────────────────────────────────────────────────────────
const rescanBtn = $("#hdr-rescan");
if (rescanBtn) {
  rescanBtn.addEventListener("click", async () => {
    if (rescanBtn.dataset.busy === "1") return;
    rescanBtn.dataset.busy = "1";
    const original = rescanBtn.textContent;
    rescanBtn.textContent = "Scanning…";
    rescanBtn.disabled = true;
    try {
      await api("/api/rescan", {});
    } catch { /* surfaced via the status pill */ }
    setTimeout(() => {
      rescanBtn.textContent = original;
      rescanBtn.disabled = false;
      rescanBtn.dataset.busy = "0";
    }, 1200);
  });
}

// ── keyboard: Tab trap + Escape ───────────────────────────────────────────
document.addEventListener("keydown", (e) => {
  if (e.key === "Tab") { _trapTab(e); return; }
  if (e.key !== "Escape") return;
  if (!$("#onboarding").hidden)      { finishTour(); return; }
  if (!$("#device-drawer").hidden)   { closeDeviceDrawer(); return; }
  if (!$("#alert-drawer").hidden)    { closeExplainer(); return; }
});

// ── boot ──────────────────────────────────────────────────────────────────
showTab(CURRENT_TAB);
refresh().then(showOnboardingIfNeeded);
startSSE();
// Fallback polling — SSE pushes deltas instantly when connected.
setInterval(refresh, 30000);
setInterval(updateLivePill, 15000);
