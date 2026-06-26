// Inglorious Network Scanner — dashboard front-end.
// Plain vanilla JS, no framework.

const $  = (sel) => document.querySelector(sel);
const $$ = (sel) => Array.from(document.querySelectorAll(sel));

const RISKY_PORTS = new Set([23, 21, 513, 514, 111, 2049, 3389, 5900, 6667, 1080]);

// "What does this mean / what should I do?" copy keyed by alert.kind prefix.
// Order matters — first matching prefix wins.
const ALERT_HELP = [
  ["rogue_dhcp", {
    title: "More than one DHCP server",
    why:   "Your router hands out IP addresses (DHCP). If two devices are doing that, your LAN is in an unstable state — at best you'll have intermittent disconnections; at worst, an attacker is intentionally redirecting traffic.",
    do:    "Most often this is a second router plugged into the LAN by mistake. Walk to your network closet, find anything that isn't your primary router (a powerline adapter, a guest AP, an old AirPort), and either unplug it or switch its DHCP off in its admin page.",
  }],
  ["arp_flap_", {
    title: "ARP / MAC instability",
    why:   "ARP is how devices on the LAN find each other. The same IP address shouldn't be answered by different hardware addresses in a short window — that's the fingerprint of someone running an ARP-spoof attack to read your traffic.",
    do:    "If you haven't restarted a router or moved a device recently, take it seriously: change your WiFi password, kick all devices off, and add them back one at a time so any unknown joiner stands out.",
  }],
  ["vendor_changed", {
    title: "Hardware mismatch on a known MAC",
    why:   "Every network card has a unique MAC and a manufacturer associated with it. If the manufacturer suddenly changes on a MAC you've seen before, it almost always means a device is pretending to be one of yours.",
    do:    "Change your WiFi password right away. Then on the router, kick everything off and let your real devices reconnect — anything that doesn't reconnect was probably the impostor.",
  }],
  ["wan_exposed_", {
    title: "Reachable from the public internet",
    why:   "Your router is forwarding a port from the public internet to this device on your LAN. Anyone in the world can try to connect to it. Most home users never need this, and most who do don't realize they have it.",
    do:    "Open your router's admin page (usually http://192.168.1.1 or http://192.168.0.1). Find the Port Forwarding or NAT / Virtual Server section. Remove the rule. While you're there, turn UPnP off — it lets devices on your LAN open WAN ports without asking you.",
  }],
  ["default_creds_risk", {
    title: "Likely default password",
    why:   "Some camera and DVR brands ship with the same admin password on every unit. If you've never changed it, anyone on the same network — or the public internet, if the device is exposed — can log in.",
    do:    "Open the device's IP in a browser, log in with the documented default, and set a long unique password. If you can't remember whether you changed it, change it now anyway.",
  }],
  ["risky_port_23", {
    title: "Telnet is exposed",
    why:   "Telnet sends passwords in plain text. No modern device should have it on. If you see it open, the device is either very old or already compromised by malware that turned it on for remote control.",
    do:    "If the device has an admin page, look for a 'disable Telnet' option. If it doesn't, treat it as malware: unplug it, factory-reset, update firmware, and reconnect only if essential.",
  }],
  ["risky_port_", {
    title: "Insecure protocol exposed",
    why:   "Older remote-access protocols like FTP, RDP, VNC, and rsh have well-known weaknesses or send credentials in plain text. Leaving them open invites brute-force attacks and traffic sniffing.",
    do:    "Disable the service if you don't actively need it. If you do, restrict it to specific source IPs in the device's firewall and put it behind a strong password.",
  }],
  ["new_device", {
    title: "A new device joined your WiFi",
    why:   "INS notices the first time it sees a hardware address. If it's yours, mark it Known and you won't be alerted again. If it isn't, your WiFi password may have leaked.",
    do:    "Recognize it? Mark Known and give it a friendly name. Don't? Change your WiFi password, kick everything off the router, and re-join your real devices.",
  }],
  ["randomized_mac_", {
    title: "Same device, different MAC",
    why:   "iPhones, recent iPads, and modern Android phones rotate their WiFi MAC for privacy. INS recognizes that a 'new' MAC actually belongs to one of your devices so you don't get an alert for the same phone every week.",
    do:    "If you trust the grouping, no action is needed. If any of the listed MACs doesn't belong to this device, mark it as Unknown and investigate.",
  }],
  ["camera_no_https", {
    title: "Camera admin page is unencrypted",
    why:   "Logging into the camera's web admin over HTTP sends your password in clear text across the LAN. Anyone with access to your WiFi (or any compromised device on it) can capture it.",
    do:    "Look in the camera's settings for an HTTPS option and turn it on. If it doesn't have one, treat the LAN password as already exposed and use it nowhere else.",
  }],
  ["dns_threat", {
    title: "Device contacted a flagged domain",
    why:   "The destination this device looked up is on a local list of known abuse, command-and-control, or phishing infrastructure. That's a strong signal of malware or a compromised app.",
    do:    "If it's an IoT device, factory-reset it. If it's a computer or phone, run a malware scan. Investigate what's installed on it that you don't recognize.",
  }],
];

let STATE   = null;
let HISTORY = [];
let CURRENT_TAB = location.hash.replace("#", "") || "overview";

// Element focused before an overlay opened, so focus can be returned on close.
let _lastFocus = null;
function _restoreFocus() {
  if (_lastFocus && typeof _lastFocus.focus === "function") _lastFocus.focus();
  _lastFocus = null;
}

// ── tab switching ─────────────────────────────────────────────────────────
function showTab(name) {
  CURRENT_TAB = name;
  history.replaceState(null, "", `#${name}`);
  $$(".navbtn").forEach(b => b.classList.toggle("active", b.dataset.tab === name));
  $$(".tab").forEach(t => t.hidden = t.id !== `tab-${name}`);
  if (name === "history") loadHistory();
}
$$(".navbtn").forEach(b => b.addEventListener("click", () => showTab(b.dataset.tab)));

// ── api helpers ───────────────────────────────────────────────────────────
async function api(path, body) {
  const opts = body
    ? { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) }
    : {};
  const r = await fetch(path, opts);
  return r.json();
}
const escHtml = (s) => String(s ?? "").replace(/[&<>"']/g, c =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#39;" }[c]));

// ── refresh loop ──────────────────────────────────────────────────────────
async function refresh() {
  try {
    // Only /api/state on the hot path. The (up-to-5000-row) scan history is
    // fetched lazily by loadHistory() when the History tab is actually shown,
    // not on every scan tick.
    STATE = await fetch("/api/state").then(r => r.json());
    paintHeader();
    paintHealth();
    paintOverview();
    paintDevices();
    paintTriage();
    paintAlerts();
    paintOverviewAlerts();
    paintKnown();
    paintWebhooks();
    paintHook();
    updateLivePill();
    if (CURRENT_TAB === "history") loadHistory();
  } catch (e) { /* network blip; try again next tick */ }
}

// Coalesce bursty SSE events (one scan can fire scan.completed + several
// device.* events) into a single repaint so we don't run the full painter
// chain N+1 times per scan.
let _refreshTimer = null;
function refreshSoon() {
  if (_refreshTimer) return;
  _refreshTimer = setTimeout(() => { _refreshTimer = null; refresh(); }, 300);
}

// Fetch a bounded recent window of scan history, then redraw the chart.
async function loadHistory() {
  try {
    HISTORY = await fetch("/api/history?limit=500").then(r => r.json());
  } catch (e) { /* keep whatever we had */ }
  drawHistory();
}

// ── header ────────────────────────────────────────────────────────────────
function paintHeader() {
  $("#hdr-ssid").textContent  = STATE.ssid || "—";
  $("#hdr-net").textContent   = STATE.network || "—";
  $("#hdr-public-ip").textContent = STATE.public_ip || "—";
  $("#hdr-count").textContent = STATE.count || 0;
  $("#hdr-alerts").textContent = STATE.unack_count || 0;
  $("#hdr-scantime").textContent = `last scan ${STATE.last_scan}`;
  $("#hdr-version").textContent = STATE.version || "";

  const aBadge = $("#nav-alert-badge");
  aBadge.textContent = STATE.unack_count ? STATE.unack_count : "";

  const tBadge = $("#nav-triage-badge");
  tBadge.textContent = (STATE.triage || []).length || "";

  // Show the SSID-permission banner only when scanning works (network CIDR
  // detected) but SSID detection failed — distinguishes "Location permission
  // needed" from "not connected to any WiFi at all".
  const banner = $("#ssid-banner");
  if (banner) {
    banner.hidden = !(STATE.network && !STATE.ssid);
  }
}

// ── health ────────────────────────────────────────────────────────────────
function paintHealth() {
  const h = STATE.health || {};
  const score = (typeof h.score === "number") ? h.score : null;

  $("#health-num").textContent = (score == null) ? "—" : String(score);

  // Ring stroke: 326.7 = 2 * π * 52 (r=52). Map 0..100 to 0..326.7 filled.
  const fg = $("#health-ring-fg");
  if (fg) {
    const off = 326.7 * (1 - (score || 0) / 100);
    fg.setAttribute("stroke-dashoffset", String(off));
  }

  const band = h.band || "—";
  const headline = h.headline || "Waiting for first scan…";

  const bandLabels = {
    excellent: "Excellent",
    good:      "Good",
    fair:      "Fair",
    poor:      "Poor",
    at_risk:   "At risk",
  };
  $("#health-band").textContent = bandLabels[band] || "Network Health";
  $("#health-band").className = `health-band band-${band}`;
  $("#health-headline").textContent = headline;
  $("#health-ring").className = `health-ring band-${band}`;

  const reasonsEl = $("#health-reasons");
  const reasons = h.reasons || [];
  if (!reasons.length) {
    reasonsEl.innerHTML = `<li class="health-reason-empty">Nothing currently dragging your score down.</li>`;
  } else {
    reasonsEl.innerHTML = reasons.slice(0, 6).map(r => `
      <li class="health-reason">
        <span class="reason-weight">−${r.weight}</span>
        <span class="reason-label">${escHtml(r.label)}</span>
      </li>
    `).join("");
  }
}

// ── overview summary cards ────────────────────────────────────────────────
function paintOverview() {
  const grid = $("#overview-summary");
  const devs = STATE.devices || [];
  const known   = devs.filter(d => d.is_known && !d.me).length;
  const unknown = devs.filter(d => !d.is_known && !d.me).length;
  const idents  = devs.filter(d => d.device_type !== "unknown").length;
  const wan     = (STATE.wan_mappings || []).length;

  grid.innerHTML = [
    {label: "Devices seen", value: devs.length, kind: "info"},
    {label: "Known",          value: known,       kind: "ok"},
    {label: "Unknown",        value: unknown,     kind: unknown ? "warn" : "ok"},
    {label: "Identified",     value: `${idents} / ${devs.length}`, kind: "info"},
    {label: "WAN exposed",    value: wan,         kind: wan ? "crit" : "ok"},
  ].map(s => `
    <div class="ov-card ov-${s.kind}">
      <div class="ov-num">${escHtml(s.value)}</div>
      <div class="ov-lbl">${escHtml(s.label)}</div>
    </div>
  `).join("");
}

function paintOverviewAlerts() {
  const list = $("#overview-alerts");
  const recent = (STATE.alerts || []).slice(0, 4);
  if (!recent.length) {
    list.innerHTML = `<div class="empty">No alerts yet.</div>`;
    return;
  }
  list.innerHTML = recent.map(alertRow).join("");
  wireAlertActions(list);
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
  if (kf === "unknown"      && d.is_known)  return false;
  if (kf === "unidentified" && d.device_type !== "unknown") return false;
  return true;
}

// Persisted across reloads. "grid" (default) or "list".
let DEVICE_VIEW = localStorage.getItem("ins.devicesView") || "grid";

function setDevicesView(mode) {
  DEVICE_VIEW = (mode === "list") ? "list" : "grid";
  localStorage.setItem("ins.devicesView", DEVICE_VIEW);
  document.querySelectorAll(".vtbtn").forEach(b =>
    b.classList.toggle("active", b.dataset.view === DEVICE_VIEW));
  $("#device-grid").hidden = DEVICE_VIEW !== "grid";
  $("#device-list").hidden = DEVICE_VIEW !== "list";
  if (STATE) paintDevices();
}
document.querySelectorAll(".vtbtn").forEach(b =>
  b.addEventListener("click", () => setDevicesView(b.dataset.view)));

// Compact list view sort state. Persisted across reloads.
// dir is "asc" or "desc"; key matches the data-sort attribute on a header cell.
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
  document.querySelectorAll(".dl-head .dl-sort").forEach(el => {
    const active = el.dataset.sort === LIST_SORT.key;
    el.classList.toggle("active", active);
    el.dataset.dir = active ? LIST_SORT.dir : "";
    el.setAttribute("aria-sort",
      active ? (LIST_SORT.dir === "asc" ? "ascending" : "descending") : "none");
  });
}

document.querySelectorAll(".dl-head .dl-sort").forEach(el =>
  el.addEventListener("click", () => setListSort(el.dataset.sort)));
applyListSortIndicators();

// Numeric (dotted-quad) compare for IPs; lexical for everything else.
function ipNum(s) {
  const parts = String(s || "").split(".").map(n => parseInt(n, 10));
  if (parts.length !== 4 || parts.some(isNaN)) return -1;
  return ((parts[0] << 24) >>> 0) + (parts[1] << 16) + (parts[2] << 8) + parts[3];
}
function sortKeyValue(d, key) {
  switch (key) {
    case "name":   return (bestName(d) || "").toLowerCase();
    case "ip":     return ipNum(d.ip);
    case "mac":    return (d.mac || "").toLowerCase();
    case "vendor": return (d.vendor || "").toLowerCase();
    case "type":   return (d.type_label || d.device_type || "").toLowerCase();
    case "ports":  return (d.ports || []).length;
    case "bw":     return currentBps(d, "total");
    default:       return "";
  }
}

// Bandwidth helpers — samples come from the server as [(ts, bytes_in, bytes_out), ...]
// each entry covering a ~60-second window flushed by the sniffer.
function currentBps(d, dir /* "in" | "out" | "total" */) {
  const s = d.bw_samples;
  if (!Array.isArray(s) || !s.length) return 0;
  const last = s[s.length - 1];
  const window = 60;  // sniffer flush cadence
  const bin  = last[1] / window;
  const bout = last[2] / window;
  if (dir === "in")  return bin;
  if (dir === "out") return bout;
  return bin + bout;
}
function fmtRate(bps) {
  if (!bps || bps < 1) return "0";
  const u = ["B/s","KB/s","MB/s","GB/s"];
  let i = 0; let v = bps;
  while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
  return (v >= 100 ? v.toFixed(0) : v.toFixed(1)) + " " + u[i];
}
function bandwidthCell(d) {
  const samples = d.bw_samples || [];
  if (!samples.length) {
    return `<div class="dl-c dl-c-bw"><span class="bw-empty">—</span></div>`;
  }
  const inBps  = currentBps(d, "in");
  const outBps = currentBps(d, "out");
  // Sparkline: 60 slots @ 1px each = 60px wide; height 18px. Use TOTAL bytes
  // (in+out) per sample so the line shape reflects "how active was this
  // device", with in/out drawn as separate strokes.
  const W = 80, H = 18;
  const slots = samples.slice(-30);
  const maxVal = Math.max(1, ...slots.map(s => Math.max(s[1], s[2])));
  const scaleX = i => (W * i) / Math.max(1, slots.length - 1);
  const scaleY = v => H - 1 - ((v / maxVal) * (H - 2));
  const path = (idx) => slots.map((s, i) =>
    `${i ? "L" : "M"}${scaleX(i).toFixed(1)} ${scaleY(s[idx]).toFixed(1)}`).join(" ");
  return `
    <div class="dl-c dl-c-bw" title="↓ ${fmtRate(inBps)}  ↑ ${fmtRate(outBps)} (last minute)">
      <svg class="bw-spark" viewBox="0 0 ${W} ${H}" preserveAspectRatio="none">
        <path class="in"  d="${escHtml(path(1))}"></path>
        <path class="out" d="${escHtml(path(2))}"></path>
      </svg>
      <div class="bw-rate">
        <b>↓ ${escHtml(fmtRate(inBps))}</b><br>
        <b>↑ ${escHtml(fmtRate(outBps))}</b>
      </div>
    </div>`;
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

function paintDevices() {
  // Rebuild type filter once per refresh to reflect newly-classified types.
  const seenTypes = new Set(STATE.devices.map(d => d.device_type).filter(Boolean));
  const sel = $("#dev-type-filter");
  const prev = sel.value;
  sel.innerHTML = `<option value="">All types</option>` +
    [...seenTypes].sort().map(t => {
      const ex = STATE.devices.find(d => d.device_type === t);
      return `<option value="${escHtml(t)}">${escHtml(ex?.type_icon || "")} ${escHtml(ex?.type_label || t)}</option>`;
    }).join("");
  if ([...seenTypes].includes(prev)) sel.value = prev;

  // Ensure the right view container is visible (handles first paint).
  $("#device-grid").hidden = DEVICE_VIEW !== "grid";
  $("#device-list").hidden = DEVICE_VIEW !== "list";

  const visible = STATE.devices.filter(deviceMatchesFilter);
  if (DEVICE_VIEW === "list") {
    paintDevicesList(visible);
  } else {
    paintDevicesGrid(visible);
  }
}

function paintDevicesGrid(visible) {
  const grid = $("#device-grid");
  if (!visible.length) {
    grid.innerHTML = `<div class="empty">No devices match the current filter.</div>`;
    return;
  }
  grid.innerHTML = visible.map(deviceCard).join("");
  grid.querySelectorAll("[data-action]").forEach(el => {
    el.addEventListener("click", onDeviceAction);
  });
}

function paintDevicesList(visible) {
  const body = $("#device-list-body");
  if (!visible.length) {
    body.innerHTML = `<div class="empty">No devices match the current filter.</div>`;
    return;
  }
  body.innerHTML = sortedForList(visible).map(deviceListRow).join("");
  body.querySelectorAll("[data-action]").forEach(el => {
    el.addEventListener("click", (e) => {
      e.stopPropagation();
      onDeviceAction(e);
    });
  });
  body.querySelectorAll("[data-row-mac]").forEach(row => {
    row.addEventListener("click", () => openDeviceStory(row.dataset.rowMac));
    row.addEventListener("keydown", (e) => {
      // Only when focus is on the row itself, not an inner action button.
      if ((e.key === "Enter" || e.key === " ") &&
          !e.target.closest("[data-action], button, input, select")) {
        e.preventDefault();
        openDeviceStory(row.dataset.rowMac);
      }
    });
  });
}

function deviceListRow(d) {
  const dotKlass = d.me ? "s-me"
                 : d.is_known ? "s-known"
                 : (d.device_type === "unknown" || (d.type_confidence ?? 0) < 0.3) ? "s-identifying"
                 : "s-unknown";
  const name = bestName(d) || "(unnamed)";
  const ports = (d.ports || []).slice(0, 6).map(p =>
    `<span class="port-chip${RISKY_PORTS.has(p) ? " risky" : ""}">${p}</span>`).join("");
  const extraPortCount = Math.max(0, (d.ports || []).length - 6);
  const action = d.me ? `<span class="dl-self">you</span>`
    : d.is_known
      ? `<button class="btn btn-tiny btn-danger" data-action="unknown" data-mac="${escHtml(d.mac)}">Unknown</button>`
      : `<button class="btn btn-tiny btn-primary" data-action="known" data-mac="${escHtml(d.mac)}" data-name="${escHtml(name)}">Mark Known</button>`;
  return `
    <div class="dl-row${d.present === false ? " is-away" : ""}" data-row-mac="${escHtml(d.mac)}" tabindex="0" aria-label="View details for ${escHtml(name)}${d.present === false ? " (last seen " + timeAgo(d.last_seen) + ")" : ""}">
      <div class="dl-c dl-c-status"><span class="dc-status ${dotKlass}"></span></div>
      <div class="dl-c dl-c-icon">${escHtml(d.type_icon || "❔")}</div>
      <div class="dl-c dl-c-name">${escHtml(name)}</div>
      <div class="dl-c dl-c-ip">${escHtml(d.ip || "—")}</div>
      <div class="dl-c dl-c-mac">${escHtml(d.mac || "—")}</div>
      <div class="dl-c dl-c-vendor">${escHtml(d.vendor || "—")}</div>
      <div class="dl-c dl-c-type">${escHtml(d.type_label || "—")}</div>
      ${bandwidthCell(d)}
      <div class="dl-c dl-c-ports">${ports}${extraPortCount ? `<span class="dl-ports-more">+${extraPortCount}</span>` : ""}</div>
      <div class="dl-c dl-c-actions">${action}</div>
    </div>`;
}

// Pick the best human-readable name we can derive from what we know about a
// device. Priority: explicit Known label > strongest probe fingerprint
// (mDNS/SSDP/SMB friendlyName, HTTP page title) > reverse-DNS hostname >
// vendor OUI lookup. Returns "" if nothing usable is available so callers
// can choose their own fallback string ("(unnamed)", "Identifying…", etc).
function bestName(d) {
  if (d.known_name)                        return d.known_name;
  if (d.fingerprint)                       return d.fingerprint;
  if (d.hostname && d.hostname !== "—")    return d.hostname.replace(/\.local\.?$/i, "");
  if (d.vendor && d.vendor !== "—")        return d.vendor;
  return "";
}

function deviceCard(d) {
  const mainName  = bestName(d);
  const subBits = [];
  if (d.ip)  subBits.push(d.ip);
  if (d.mac) subBits.push(d.mac);
  if (d.present === false) subBits.push(`last seen ${timeAgo(d.last_seen)}`);
  else if (d.latency != null) subBits.push(`${d.latency} ms`);

  // Confidence-aware classes: gray ("identifying") when we haven't classified yet.
  const unidentified = (d.device_type === "unknown" || (d.type_confidence ?? 0) < 0.3);
  const klass = d.me ? "is-me"
              : d.is_known ? "is-known"
              : unidentified ? "is-identifying"
              : "is-unknown";
  const dotKlass = d.me ? "s-me"
                 : d.is_known ? "s-known"
                 : unidentified ? "s-identifying"
                 : "s-unknown";

  const ports = (d.ports || []).map(p => {
    const risky = RISKY_PORTS.has(p);
    return `<span class="port-chip${risky ? " risky" : ""}">${p}</span>`;
  }).join("");

  const meta = [];
  meta.push(`<dt>Type</dt><dd>${escHtml(d.type_icon || "")} ${escHtml(d.type_label || "Identifying…")}</dd>`);
  if (d.vendor && d.vendor !== "—") meta.push(`<dt>Vendor</dt><dd>${escHtml(d.vendor)}</dd>`);
  if (d.fingerprint)                meta.push(`<dt>Identity</dt><dd>${escHtml(d.fingerprint)}</dd>`);
  if (d.first_seen)                 meta.push(`<dt>First seen</dt><dd>${escHtml(timeAgo(d.first_seen))}</dd>`);
  if ((d.wan_exposed || []).length) {
    meta.push(`<dt>WAN exposed</dt><dd class="warn">${(d.wan_exposed || []).map(m => `:${escHtml(m.external_port)}/${escHtml(m.protocol)}`).join(" ")}</dd>`);
  }

  const probeToggle = d.me ? "" : `
    <button class="btn btn-ghost btn-tiny" data-action="probe" data-mac="${escHtml(d.mac)}" data-state="${d.no_probe ? "1" : "0"}">
      ${d.no_probe ? "Resume probing" : "Don't probe this device"}
    </button>`;

  const actions = d.me ? "" : `
    <div class="dc-actions">
      ${d.is_known
        ? `<button class="btn btn-danger" data-action="unknown" data-mac="${escHtml(d.mac)}">Remove from Known</button>`
        : `<button class="btn btn-primary" data-action="known"   data-mac="${escHtml(d.mac)}" data-name="${escHtml(mainName || "")}">Mark as Known</button>`}
      <button class="btn" data-action="wol" data-mac="${escHtml(d.mac)}">Wake</button>
      ${probeToggle}
    </div>`;

  return `
    <article class="device-card ${klass}${d.present === false ? " is-away" : ""}" tabindex="0" aria-label="View details for ${escHtml(mainName || d.ip || "device")}">
      <div class="dc-head">
        <div class="dc-typeicon">${escHtml(d.type_icon || "❔")}</div>
        <div class="dc-name">
          <div class="dc-name-main">${escHtml(mainName || "(unnamed)")}</div>
          <div class="dc-name-sub">${escHtml(subBits.join("  ·  "))}</div>
        </div>
        <div class="dc-status ${dotKlass}"></div>
      </div>
      <dl class="dc-meta">${meta.join("")}</dl>
      ${ports ? `<div class="dc-ports">${ports}</div>` : ""}
      ${actions}
    </article>`;
}

async function onDeviceAction(e) {
  const el = e.currentTarget;
  const mac = el.dataset.mac;
  const action = el.dataset.action;
  if (action === "known") {
    const name = prompt("Name for this device:", el.dataset.name || "");
    if (name === null) return;   // Cancel aborts — don't mark the device Known
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
  document.querySelector(s).addEventListener("input", paintDevices));

// ── triage ────────────────────────────────────────────────────────────────
function paintTriage() {
  const list = $("#triage-list");
  // Don't rebuild the list out from under someone typing a device name — the
  // ~30s scan cadence would otherwise wipe a half-typed entry. Scoped to the
  // name INPUT specifically: guarding the whole list would also suppress the
  // post-action repaint when an action button is focused (Chromium focuses
  // buttons on click), leaving a just-actioned device visibly stuck.
  if (document.activeElement && document.activeElement.matches("#triage-list .triage-name")) return;
  const items = STATE.triage || [];
  if (!items.length) {
    list.innerHTML = `<div class="empty">Nothing to triage — every device is marked as known.</div>`;
    return;
  }
  list.innerHTML = items.map(d => {
    const suggested = bestName(d);
    return `
      <div class="triage-row" data-mac="${escHtml(d.mac)}">
        <div class="triage-icon">${escHtml(d.type_icon || "❔")}</div>
        <div class="triage-info">
          <div class="triage-title">${escHtml(d.type_label || "Unknown device")} <span class="triage-vendor">${escHtml(d.vendor || "")}</span></div>
          <div class="triage-sub">${escHtml(d.ip)} · ${escHtml(d.mac)} · first seen ${escHtml(timeAgo(d.first_seen || 0))}</div>
          ${d.fingerprint ? `<div class="triage-fp">${escHtml(d.fingerprint)}</div>` : ""}
        </div>
        <input type="text" class="triage-name" aria-label="Device name" placeholder="Name this device" value="${escHtml(suggested)}">
        <button class="btn btn-primary" data-triage-act="known">Mark Known</button>
        <button class="btn btn-danger"  data-triage-act="block">Block / Ignore</button>
      </div>`;
  }).join("");

  list.querySelectorAll("[data-triage-act]").forEach(b => {
    b.addEventListener("click", async () => {
      const row = b.closest(".triage-row");
      const mac = row.dataset.mac;
      const act = b.dataset.triageAct;
      if (act === "known") {
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
  if (!confirm(`Mark ${entries.length} device${entries.length === 1 ? "" : "s"} as Known?`)) return;
  await api("/api/triage/bulk_known", { entries });
  refresh();
});

// ── alerts ────────────────────────────────────────────────────────────────
function paintAlerts() {
  const list = $("#alerts-list");
  const alerts = STATE.alerts || [];
  if (!alerts.length) {
    list.innerHTML = `<div class="empty">No alerts yet. New devices and risky ports will show up here.</div>`;
    return;
  }
  list.innerHTML = alerts.map(alertRow).join("");
  wireAlertActions(list);
}

// Stroke SVG severity glyphs. Keeps icons consistent across the dashboard and
// avoids the AI-emoji look on a security-ops surface.
const SEV_ICON = {
  critical: `<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="9.25"/><path d="M12 8v5"/><circle cx="12" cy="16.4" r=".7" fill="currentColor" stroke="none"/></svg>`,
  warning:  `<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M10.66 3.62 1.95 18.5a1.55 1.55 0 0 0 1.34 2.33h17.42a1.55 1.55 0 0 0 1.34-2.33L13.34 3.62a1.55 1.55 0 0 0-2.68 0Z"/><path d="M12 10v4"/><circle cx="12" cy="17.4" r=".7" fill="currentColor" stroke="none"/></svg>`,
  info:     `<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="9.25"/><path d="M12 11.2v4.6"/><circle cx="12" cy="8.2" r=".75" fill="currentColor" stroke="none"/></svg>`,
};

function alertRow(a) {
  const sev  = a.severity || "info";
  const icon = SEV_ICON[sev] || SEV_ICON.info;
  return `
    <div class="alert-row sev-${escHtml(sev)} ${a.acknowledged ? "is-ack" : ""}" data-alert-kind="${escHtml(a.kind)}">
      <div class="alert-sev">${icon}</div>
      <div class="alert-body">
        <div class="alert-title">${escHtml(a.title)}</div>
        <div class="alert-msg">${escHtml(a.message)}</div>
        <div class="alert-time">${escHtml(timeAgo(a.ts))}  ·  ${escHtml(a.kind)}</div>
      </div>
      <div class="alert-actions">
        <button class="btn btn-ghost btn-tiny" data-explain="${escHtml(a.kind)}">What does this mean?</button>
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
  $("#drawer-close").focus();
}
function closeExplainer() {
  $("#alert-drawer").hidden = true;
  $("#drawer-scrim").hidden = true;
  _restoreFocus();
}
$("#drawer-close").addEventListener("click", closeExplainer);
$("#drawer-scrim").addEventListener("click", closeExplainer);

// ── history chart ─────────────────────────────────────────────────────────
function drawHistory() {
  const canvas = $("#history-chart");
  if (!canvas) return;
  // Read the live design tokens so the chart matches the rest of the dashboard
  // (the redesign moved off the old neon-cyan palette). Fall back if unset.
  const cssVar = (name, fb) =>
    (getComputedStyle(document.documentElement).getPropertyValue(name).trim() || fb);
  const accent = cssVar("--accent", "#6BBDC6");
  const grid   = cssVar("--border", "rgba(255,255,255,.06)");
  const labelC = cssVar("--text-3", "#8A92A1");
  const mono   = "10px ui-monospace, 'Geist Mono', monospace";
  const dpr = window.devicePixelRatio || 1;
  const w = canvas.clientWidth, h = canvas.clientHeight;
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
  const min = 0;
  const padX = 40, padY = 20;
  const innerW = w - padX * 2, innerH = h - padY * 2;
  const xs = (i) => padX + (i / (HISTORY.length - 1 || 1)) * innerW;
  const ys = (v) => padY + innerH - ((v - min) / (max - min || 1)) * innerH;

  ctx.strokeStyle = grid;
  ctx.lineWidth = 1;
  for (let i = 0; i <= 4; i++) {
    const y = padY + (innerH * i) / 4;
    ctx.beginPath(); ctx.moveTo(padX, y); ctx.lineTo(w - padX, y); ctx.stroke();
  }

  ctx.strokeStyle = accent;
  ctx.lineWidth = 1.5;
  ctx.beginPath();
  HISTORY.forEach((p, i) => {
    if (i === 0) ctx.moveTo(xs(i), ys(p.count));
    else ctx.lineTo(xs(i), ys(p.count));
  });
  ctx.stroke();

  ctx.lineTo(xs(HISTORY.length - 1), padY + innerH);
  ctx.lineTo(xs(0), padY + innerH);
  ctx.closePath();
  ctx.globalAlpha = 0.08;
  ctx.fillStyle = accent;
  ctx.fill();
  ctx.globalAlpha = 1;

  ctx.fillStyle = labelC;
  ctx.font = mono;
  ctx.textAlign = "right";
  for (let i = 0; i <= 4; i++) {
    const v = Math.round(max - ((max - min) * i) / 4);
    ctx.fillText(String(v), padX - 8, padY + (innerH * i) / 4 + 3);
  }
}

// ── known list ────────────────────────────────────────────────────────────
function paintKnown() {
  const list = $("#known-list");
  const entries = Object.entries(STATE.known || {});
  if (!entries.length) {
    list.innerHTML = `<div class="empty">No devices marked as Known yet.</div>`;
    return;
  }
  list.innerHTML = entries.map(([mac, info]) => `
    <div class="known-row">
      <span class="km">${escHtml(mac)}</span>
      <span class="kn">${escHtml(info.name || "(no label)")}</span>
      <button class="btn btn-danger" data-known-remove="${escHtml(mac)}">Remove</button>
    </div>
  `).join("");
  list.querySelectorAll("[data-known-remove]").forEach(b =>
    b.addEventListener("click", async () => {
      await api("/api/known/remove", { mac: b.dataset.knownRemove });
      refresh();
    }));
}

// ── webhooks ──────────────────────────────────────────────────────────────
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

// ── hook script ───────────────────────────────────────────────────────────
function paintHook() {
  const ta = $("#hook-script");
  if (document.activeElement !== ta) {
    ta.value = STATE.hook || "";
  }
}
$("#hook-save").addEventListener("click", async () => {
  await api("/api/hook", { script: $("#hook-script").value });
});

// ── utils ─────────────────────────────────────────────────────────────────
function timeAgo(tsSeconds) {
  if (!tsSeconds) return "just now";
  const diff = Date.now() / 1000 - tsSeconds;
  if (diff < 60)      return `${Math.round(diff)}s ago`;
  if (diff < 3600)    return `${Math.round(diff / 60)}m ago`;
  if (diff < 86400)   return `${Math.round(diff / 3600)}h ago`;
  return `${Math.round(diff / 86400)}d ago`;
}

// ── device story drawer ──────────────────────────────────────────────────
async function openDeviceStory(mac) {
  const opener = document.activeElement;
  try {
    const story = await fetch(`/api/device/${encodeURIComponent(mac)}`).then(r => r.json());
    if (!story || story.error) return;
    _lastFocus = opener;
    const d = story.device || {};
    const name = story.known_name || d.hostname || d.vendor || mac;
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
          const icon = SEV_ICON[sev] || SEV_ICON.info;
          return `
            <div class="dstory-alert sev-${escHtml(sev)}">
              <div class="dstory-alert-head"><span class="dstory-alert-icon">${icon}</span><strong>${escHtml(a.title)}</strong></div>
              <div class="dstory-alert-msg">${escHtml(a.message)}</div>
              <div class="dstory-alert-ts">${escHtml(new Date(a.ts * 1000).toLocaleString())}${a.acknowledged ? " · acknowledged" : ""}</div>
            </div>`;
        }).join("")
      : `<div class="empty">No alerts triggered by this device.</div>`;

    const ports = (d.ports || []).length
      ? (d.ports || []).map(p => `<span class="port-chip${RISKY_PORTS.has(p) ? " risky" : ""}">${p}</span>`).join("")
      : `<span class="empty-inline">No ports observed open.</span>`;

    const wan = (story.wan_exposed || []).length
      ? (story.wan_exposed || []).map(m => `<div class="dstory-wan">${SEV_ICON.warning} External port ${escHtml(m.external_port)}/${escHtml(m.protocol)} forwarded to internal port ${escHtml(m.internal_port)}</div>`).join("")
      : "";

    const routerKind = (STATE.settings && STATE.settings.router_kind) || "none";
    const blockButton = (routerKind === "none" || d.me)
      ? ""
      : `<button class="btn btn-danger" id="router-block-mac" data-mac="${escHtml(d.mac)}">Block on router</button>
         <button class="btn" id="router-unblock-mac" data-mac="${escHtml(d.mac)}">Unblock</button>`;

    $("#device-drawer-body").innerHTML = `
      ${blockButton ? `<div class="dstory-router-actions">${blockButton}<span class="dstory-router-status" id="dstory-router-status"></span></div>` : ""}
      <h3>Identity</h3>
      <dl class="dstory-meta">
        <dt>IP</dt><dd>${escHtml(d.ip || "—")}</dd>
        <dt>MAC</dt><dd>${escHtml(d.mac || "—")}</dd>
        <dt>Vendor</dt><dd>${escHtml(d.vendor || "—")}</dd>
        <dt>Type</dt><dd>${escHtml(d.device_type || "unknown")} (${Math.round((d.type_confidence || 0) * 100)}% confidence)</dd>
        <dt>First seen</dt><dd>${escHtml(d.first_seen ? new Date(d.first_seen * 1000).toLocaleString() : "—")}</dd>
        <dt>Last seen</dt><dd>${escHtml(d.last_seen ? new Date(d.last_seen * 1000).toLocaleString() : "—")}</dd>
        <dt>Times seen</dt><dd>${escHtml(d.seen_count || 0)}</dd>
        <dt>Known</dt><dd>${story.is_known ? `<strong>${escHtml(story.known_name || "yes")}</strong>` : "no"}</dd>
      </dl>
      ${wan}
      <h3>Ports</h3>
      <div class="dc-ports">${ports}</div>
      <h3>Recent sightings (${sightings.length})</h3>
      <div class="dstory-list">${sightingsHtml}</div>
      ${renderBandwidthBlock(story.bandwidth || [])}
      ${renderDnsBlock(story.dns || [])}
      <h3>Alerts triggered (${alerts.length})</h3>
      <div class="dstory-list">${alertsHtml}</div>
    `;

    $("#device-drawer").hidden = false;
    $("#drawer-scrim").hidden = false;
    $("#device-drawer-close").focus();

    const wireRouter = (sel, path, verb) =>
      document.getElementById(sel)?.addEventListener("click", async (e) => {
        const btn = e.currentTarget;
        const status = $("#dstory-router-status");
        const mac = btn.dataset.mac;
        if (verb === "block" && !confirm(`Block ${mac} on your router? They'll be kicked off the WiFi immediately.`)) return;
        status.textContent = `${verb}ing…`;
        const r = await api(path, { mac });
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
            <div class="empty">No data yet — bandwidth monitoring requires the passive sniffer (Settings → Sniffer status).</div>`;
  }
  const totalIn  = samples.reduce((s, r) => s + (r.bytes_in  || 0), 0);
  const totalOut = samples.reduce((s, r) => s + (r.bytes_out || 0), 0);
  const max = Math.max(...samples.map(r => Math.max(r.bytes_in, r.bytes_out)), 1);
  const bars = samples.slice(-60).map(r => {
    const inH  = Math.max(2, Math.round((r.bytes_in  / max) * 36));
    const outH = Math.max(2, Math.round((r.bytes_out / max) * 36));
    return `<span class="bw-pair" title="${new Date(r.ts * 1000).toLocaleTimeString()}: in ${fmtBytes(r.bytes_in)} / out ${fmtBytes(r.bytes_out)}">
              <span class="bw-bar bw-in"  style="height:${inH}px"></span>
              <span class="bw-bar bw-out" style="height:${outH}px"></span>
            </span>`;
  }).join("");
  return `<h3>Bandwidth (last hour)</h3>
          <div class="bw-summary">Down: <strong>${fmtBytes(totalIn)}</strong>  ·  Up: <strong>${fmtBytes(totalOut)}</strong></div>
          <div class="bw-chart">${bars}</div>`;
}

function renderDnsBlock(queries) {
  if (!queries.length) {
    return `<h3>DNS lookups</h3>
            <div class="empty">No DNS logged for this device. Requires the passive sniffer.</div>`;
  }
  const rows = queries.slice(0, 25).map(q => `
    <div class="dstory-row">
      <span class="dstory-ts">${escHtml(new Date(q.ts * 1000).toLocaleString())}</span>
      <span class="dstory-ip">${escHtml(q.qname)}</span>
    </div>`).join("");
  return `<h3>DNS lookups (${queries.length})</h3>
          <div class="dstory-list">${rows}</div>`;
}

function closeDeviceDrawer() {
  $("#device-drawer").hidden = true;
  if ($("#alert-drawer").hidden) $("#drawer-scrim").hidden = true;
  _restoreFocus();
}
$("#device-drawer-close").addEventListener("click", closeDeviceDrawer);
$("#drawer-scrim").addEventListener("click", closeDeviceDrawer);

// Click anywhere on a device card (outside its buttons) to open the story.
function _macFromCard(card) {
  return card.querySelector("[data-mac]")?.dataset.mac
       || card.querySelector(".dc-name-sub")?.textContent.match(/[0-9A-F:]{17}/)?.[0];
}
$("#device-grid").addEventListener("click", (e) => {
  if (e.target.closest("[data-action], button, input, select")) return;
  const card = e.target.closest(".device-card");
  if (!card) return;
  const mac = _macFromCard(card);
  if (mac) openDeviceStory(mac);
});
// Keyboard: Enter/Space on a focused card opens the story (cards are
// tabindex=0). The guard skips inner action buttons, which handle themselves.
$("#device-grid").addEventListener("keydown", (e) => {
  if (e.key !== "Enter" && e.key !== " ") return;
  if (e.target.closest("[data-action], button, input, select")) return;
  const card = e.target.closest(".device-card");
  if (!card) return;
  e.preventDefault();
  const mac = _macFromCard(card);
  if (mac) openDeviceStory(mac);
});

// ── onboarding tour ──────────────────────────────────────────────────────
const TOUR_STEPS = [
  {
    title: "Welcome to Inglorious Network Scanner",
    body:  "INS continuously watches everything on your WiFi and tells you in plain English when something deserves attention. Three quick things before you dive in.",
  },
  {
    title: "Your Network Health Score",
    body:  "The big number on the Overview tab is a 0–100 read of how safe your network looks right now. 100 means all clear; anything lower tells you exactly what to fix and by how much it would help.",
  },
  {
    title: "Triage your unknown devices",
    body:  "The Triage tab queues every device you haven't named yet. Spend two minutes naming the ones you recognize (your phone, your TV, the printer) so future joins of those devices stop worrying you. If you don't recognize one — change your WiFi password and remove it from the router.",
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

// ── settings (voice / shortcuts) ─────────────────────────────────────────
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
      snEl.textContent = `✓ Running — ${sn.packets || 0} packets captured`;
    } else if (sn.reason) {
      snEl.textContent = `✗ Not active — ${sn.reason}`;
    } else {
      snEl.textContent = "✗ Not active — run tools/enable_sniffer.sh with sudo, then restart INS";
    }
  }
}

$("#keep-alive-save")?.addEventListener("click", async () => {
  const status = $("#keep-alive-status");
  status.textContent = "Applying…";
  const r = await fetch("/api/settings/save", {
    method: "POST", headers: {"Content-Type": "application/json"},
    body: JSON.stringify({ keep_alive: $("#setting-keep-alive").checked ? "1" : "0" }),
  }).then(r => r.json());
  if (r.ok) {
    status.textContent = "Applied ✓";
  } else {
    status.textContent = `✗ ${r.error || "failed"}`;
  }
  setTimeout(() => { status.textContent = ""; }, 3000);
  refresh();
});
$("#settings-save")?.addEventListener("click", async () => {
  const status = $("#settings-status");
  status.textContent = "Saving…";
  await api("/api/settings/save", {
    voice_enabled:          $("#setting-voice").checked ? "1" : "0",
    shortcut_on_new_device: $("#setting-shortcut-new").value.trim(),
    shortcut_on_alert:      $("#setting-shortcut-alert").value.trim(),
  });
  status.textContent = "Saved ✓";
  setTimeout(() => { status.textContent = ""; }, 1500);
  refresh();
});

// ── router config UI ───────────────────────────────────────────────────────
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
  // Show / hide kind-specific rows.
  const k = (s.router_kind || "none");
  document.querySelectorAll("[data-router-unifi]").forEach(el =>
    el.hidden = (k !== "unifi"));
  document.querySelectorAll("[data-router-openwrt]").forEach(el =>
    el.hidden = (k !== "openwrt"));
}
$("#router-kind")?.addEventListener("change", () => {
  const k = $("#router-kind").value;
  document.querySelectorAll("[data-router-unifi]").forEach(el =>
    el.hidden = (k !== "unifi"));
  document.querySelectorAll("[data-router-openwrt]").forEach(el =>
    el.hidden = (k !== "openwrt"));
});
$("#router-save")?.addEventListener("click", async () => {
  const status = $("#router-status");
  status.textContent = "Saving…";
  const body = {
    router_kind:     $("#router-kind").value,
    router_host:     $("#router-host").value.trim(),
    router_user:     $("#router-user").value.trim(),
    router_site:     $("#router-site").value.trim() || "default",
    router_ssh_port: $("#router-ssh-port").value.trim() || "22",
    router_iface:    $("#router-iface").value.trim() || "0",
  };
  const pwd = $("#router-pass").value;
  if (pwd) body.router_pass = pwd;
  await api("/api/settings/save", body);
  $("#router-pass").value = "";
  status.textContent = "Saved ✓";
  setTimeout(() => { status.textContent = ""; }, 1500);
  refresh();
});
$("#router-test")?.addEventListener("click", async () => {
  const status = $("#router-status");
  status.textContent = "Testing…";
  const r = await fetch("/api/router/test", {method: "POST", headers: {"Content-Type": "application/json"}, body: "{}"}).then(r => r.json());
  status.textContent = r.ok ? `✓ ${r.message}` : `✗ ${r.message}`;
});
const _prev_paintSettings_router = paintSettings;
paintSettings = function() { _prev_paintSettings_router(); paintRouterSettings(); };

// Add settings paint to the refresh chain.
const _origPaintHook = paintHook;
paintHook = function() { _origPaintHook(); paintSettings(); };

// ── SSE live updates ─────────────────────────────────────────────────────
// Subscribe to the server-side event bus so dashboard updates feel instant
// instead of waiting on the polling tick. We KEEP a 30s polling fallback in
// case the SSE connection drops (corporate proxies sometimes kill long
// HTTP requests after a minute or two).
let SSE_STATE = "connecting";   // "live" | "offline"

function startSSE() {
  // No EventSource (or it throws): live push isn't available — reflect that
  // honestly instead of leaving the pill on a misleading pulsing green "live".
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
      // EventSource auto-retries transient drops (readyState CONNECTING). Only
      // surface "offline" once it has actually given up (CLOSED), so the pill
      // doesn't flicker amber on every routine reconnect.
      if (es.readyState === EventSource.CLOSED) { SSE_STATE = "offline"; updateLivePill(); }
    };
  } catch (e) { SSE_STATE = "polling"; updateLivePill(); }
}

// Reflect live-update health in the header pill: green "live" by default,
// amber "stale" when the last scan is older than expected, red "offline" when
// the event stream has dropped. Purely client-side — no new network calls.
function updateLivePill() {
  const pill = document.querySelector(".live-pill");
  if (!pill) return;
  let cls = "", label = "live";
  const epoch = STATE && STATE.last_scan_epoch;
  const err   = STATE && STATE.last_scan_error;
  if (err && (!epoch || err >= epoch)) {
    // The latest scan attempt failed more recently than the last success.
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
  if (pill.lastChild) pill.lastChild.textContent = " " + label;
}

// ── Wi-Fi neighbor survey ────────────────────────────────────────────────
function rssiKlass(r) {
  if (r >= -55) return "strong";
  if (r >= -75) return "weak";
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
    <div class="wh-row${n.is_current ? " current" : ""}">
      <div class="wh-ssid"><b>${escHtml(n.ssid || "(hidden)")}</b>${n.is_current ? '<span class="you">connected</span>' : ""}</div>
      <div class="wh-bssid">${escHtml(n.bssid || "—")}</div>
      <div class="wh-band">${escHtml(n.band || "—")}</div>
      <div class="wh-channel">${n.channel || "—"}</div>
      <div class="wh-rssi ${rssiKlass(n.rssi)}">${n.rssi} dBm</div>
      <div class="wh-sec">${escHtml(n.security || "—")}</div>
    </div>`).join("");
  list.innerHTML = `
    <div class="wh-head">
      <div>SSID</div><div>BSSID</div><div>Band</div><div>Ch</div><div>RSSI</div><div>Security</div>
    </div>${rows}`;
  // Channel-occupancy chart per band — count strongest neighbor per channel.
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
      const h = r != null ? Math.max(8, Math.min(60, 64 + r)) : 6; // RSSI -64→0, -4→60
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

// ── header rescan button ─────────────────────────────────────────────────
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
    } catch { /* surface failure via the status pill, not a noisy alert */ }
    setTimeout(() => {
      rescanBtn.textContent = original;
      rescanBtn.disabled = false;
      rescanBtn.dataset.busy = "0";
    }, 1200);
  });
}

// Escape closes the topmost open overlay (onboarding > device drawer > alert
// drawer), the standard expected affordance for keyboard users.
document.addEventListener("keydown", (e) => {
  if (e.key !== "Escape") return;
  if (!$("#onboarding").hidden)      { finishTour(); return; }
  if (!$("#device-drawer").hidden)   { closeDeviceDrawer(); return; }
  if (!$("#alert-drawer").hidden)    { closeExplainer(); return; }
});

// ── boot ──────────────────────────────────────────────────────────────────
showTab(CURRENT_TAB);
setDevicesView(DEVICE_VIEW);   // honor persisted preference; sync toggle UI
refresh().then(showOnboardingIfNeeded);
startSSE();
// Fallback polling — far less frequent now that SSE pushes deltas instantly.
setInterval(refresh, 30000);
// Refresh the live/stale pill on its own cadence so staleness shows even when
// no scan events are arriving.
setInterval(updateLivePill, 15000);
