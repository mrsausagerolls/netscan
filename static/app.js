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

// ── tab switching ─────────────────────────────────────────────────────────
function showTab(name) {
  CURRENT_TAB = name;
  history.replaceState(null, "", `#${name}`);
  $$(".navbtn").forEach(b => b.classList.toggle("active", b.dataset.tab === name));
  $$(".tab").forEach(t => t.hidden = t.id !== `tab-${name}`);
  if (name === "history") drawHistory();
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
    const [state, hist] = await Promise.all([
      fetch("/api/state").then(r => r.json()),
      fetch("/api/history").then(r => r.json()),
    ]);
    STATE   = state;
    HISTORY = hist;
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
    if (CURRENT_TAB === "history") drawHistory();
  } catch (e) { /* network blip; try again next tick */ }
}

// ── header ────────────────────────────────────────────────────────────────
function paintHeader() {
  $("#hdr-ssid").textContent  = STATE.ssid || "—";
  $("#hdr-net").textContent   = STATE.network || "—";
  $("#hdr-count").textContent = STATE.count || 0;
  $("#hdr-alerts").textContent = STATE.unack_count || 0;
  $("#hdr-scantime").textContent = `last scan ${STATE.last_scan}`;
  $("#hdr-version").textContent = STATE.version || "";

  const aBadge = $("#nav-alert-badge");
  aBadge.textContent = STATE.unack_count ? STATE.unack_count : "";

  const tBadge = $("#nav-triage-badge");
  tBadge.textContent = (STATE.triage || []).length || "";
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
    {label: "Devices online", value: devs.length, kind: "info"},
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
    const blob = `${d.ip} ${d.mac} ${d.hostname} ${d.vendor} ${d.known_name} ${d.type_label}`.toLowerCase();
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

  const grid = $("#device-grid");
  const visible = STATE.devices.filter(deviceMatchesFilter);
  if (!visible.length) {
    grid.innerHTML = `<div class="empty">No devices match the current filter.</div>`;
    return;
  }
  grid.innerHTML = visible.map(deviceCard).join("");
  grid.querySelectorAll("[data-action]").forEach(el => {
    el.addEventListener("click", onDeviceAction);
  });
}

function deviceCard(d) {
  const mainName  = d.known_name || (d.hostname !== "—" ? d.hostname : d.vendor);
  const subBits = [];
  if (d.ip)  subBits.push(d.ip);
  if (d.mac) subBits.push(d.mac);
  if (d.latency != null) subBits.push(`${d.latency} ms`);

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
    meta.push(`<dt>WAN exposed</dt><dd class="warn">${(d.wan_exposed || []).map(m => `:${m.external_port}/${m.protocol}`).join(" ")}</dd>`);
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
    <article class="device-card ${klass}">
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
    const name = prompt("Name for this device:", el.dataset.name || "") ?? "";
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
  const items = STATE.triage || [];
  if (!items.length) {
    list.innerHTML = `<div class="empty">Nothing to triage — every device is marked as known.</div>`;
    return;
  }
  list.innerHTML = items.map(d => {
    const suggested = d.known_name || d.hostname && d.hostname !== "—" ? d.hostname : d.vendor || "";
    return `
      <div class="triage-row" data-mac="${escHtml(d.mac)}">
        <div class="triage-icon">${escHtml(d.type_icon || "❔")}</div>
        <div class="triage-info">
          <div class="triage-title">${escHtml(d.type_label || "Unknown device")} <span class="triage-vendor">${escHtml(d.vendor || "")}</span></div>
          <div class="triage-sub">${escHtml(d.ip)} · ${escHtml(d.mac)} · first seen ${escHtml(timeAgo(d.first_seen || 0))}</div>
          ${d.fingerprint ? `<div class="triage-fp">${escHtml(d.fingerprint)}</div>` : ""}
        </div>
        <input type="text" class="triage-name" placeholder="Name this device" value="${escHtml(suggested)}">
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

function alertRow(a) {
  const sev  = a.severity || "info";
  const icon = sev === "critical" ? "🚨" : sev === "warning" ? "⚠️" : "📡";
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
  $("#drawer-title").textContent = help.title;
  $("#drawer-body").innerHTML = `
    <h3>Why this matters</h3>
    <p>${escHtml(help.why)}</p>
    <h3>What to do</h3>
    <p>${escHtml(help.do)}</p>
  `;
  $("#alert-drawer").hidden = false;
  $("#drawer-scrim").hidden = false;
}
function closeExplainer() {
  $("#alert-drawer").hidden = true;
  $("#drawer-scrim").hidden = true;
}
$("#drawer-close").addEventListener("click", closeExplainer);
$("#drawer-scrim").addEventListener("click", closeExplainer);

// ── history chart ─────────────────────────────────────────────────────────
function drawHistory() {
  const canvas = $("#history-chart");
  if (!canvas) return;
  const dpr = window.devicePixelRatio || 1;
  const w = canvas.clientWidth, h = canvas.clientHeight;
  canvas.width = w * dpr; canvas.height = h * dpr;
  const ctx = canvas.getContext("2d");
  ctx.scale(dpr, dpr);
  ctx.clearRect(0, 0, w, h);
  if (!HISTORY.length) {
    ctx.fillStyle = "#4A5F7A";
    ctx.font = "11px JetBrains Mono";
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

  ctx.strokeStyle = "#1A2438";
  ctx.lineWidth = 1;
  for (let i = 0; i <= 4; i++) {
    const y = padY + (innerH * i) / 4;
    ctx.beginPath(); ctx.moveTo(padX, y); ctx.lineTo(w - padX, y); ctx.stroke();
  }

  ctx.strokeStyle = "#00D9F5";
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
  ctx.fillStyle = "rgba(0,217,245,.08)";
  ctx.fill();

  ctx.fillStyle = "#4A5F7A";
  ctx.font = "10px JetBrains Mono";
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

// ── boot ──────────────────────────────────────────────────────────────────
showTab(CURRENT_TAB);
refresh();
setInterval(refresh, 3000);
