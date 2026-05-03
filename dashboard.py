"""Local web dashboard — serves on http://localhost:8765"""

import json
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

PORT = 8765

_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>NetScan</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600&family=DM+Sans:opsz,wght@9..40,400;9..40,500;9..40,600&display=swap" rel="stylesheet">
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#07090D;--bg1:#0C1018;--bg2:#111722;
  --border:#1A2438;--border2:#1F2D42;
  --text:#D8E2F0;--text2:#6B7E96;--text3:#374A60;
  --green:#0DCC72;--green-a:rgba(13,204,114,.1);
  --red:#F0435A;--red-a:rgba(240,67,90,.07);
  --blue:#3AAFE8;--blue-a:rgba(58,175,232,.1);
  --cyan:#00D9F5;--cyan-a:rgba(0,217,245,.08);
  --yellow:#F5A623;
  --mono:'JetBrains Mono',monospace;
  --ui:'DM Sans',system-ui,sans-serif;
}
html,body{height:100%;overflow:hidden}
body{background:var(--bg);color:var(--text);font-family:var(--ui);font-size:13px;line-height:1.5;display:flex;flex-direction:column}
::-webkit-scrollbar{width:5px;height:5px}
::-webkit-scrollbar-track{background:transparent}
::-webkit-scrollbar-thumb{background:var(--border2);border-radius:3px}

/* ── HEADER ── */
header{
  display:flex;align-items:center;gap:0;
  height:52px;padding:0 20px;
  background:var(--bg1);
  border-bottom:1px solid var(--border);
  flex-shrink:0;position:relative;z-index:20;
}
header::after{content:'';position:absolute;bottom:0;left:0;right:0;height:1px;background:linear-gradient(90deg,rgba(0,217,245,.5),transparent 55%)}
.brand{display:flex;align-items:center;gap:9px;margin-right:20px;flex-shrink:0}
.brand-mark{
  width:30px;height:30px;border-radius:6px;
  background:var(--cyan-a);border:1px solid rgba(0,217,245,.2);
  display:flex;align-items:center;justify-content:center;font-size:15px;
}
.brand-name{font-family:var(--mono);font-size:12px;font-weight:600;letter-spacing:.1em;color:var(--cyan);text-transform:uppercase}
.hdiv{width:1px;height:24px;background:var(--border);margin:0 16px;flex-shrink:0}
.hstat{display:flex;flex-direction:column;gap:0;margin-right:16px;flex-shrink:0}
.hstat-l{font-size:9px;font-weight:600;text-transform:uppercase;letter-spacing:.08em;color:var(--text3)}
.hstat-v{font-family:var(--mono);font-size:12px;font-weight:500;color:var(--text);margin-top:1px}
.hright{margin-left:auto;display:flex;align-items:center;gap:12px}
.live-pill{
  display:flex;align-items:center;gap:7px;padding:5px 11px;
  background:rgba(13,204,114,.08);border:1px solid rgba(13,204,114,.18);
  border-radius:20px;font-size:11px;font-weight:500;color:var(--green)
}
.live-dot{width:6px;height:6px;border-radius:50%;background:var(--green);animation:livepulse 2s infinite}
@keyframes livepulse{0%{box-shadow:0 0 0 0 rgba(13,204,114,.6)}70%{box-shadow:0 0 0 5px rgba(13,204,114,0)}100%{box-shadow:0 0 0 0 rgba(13,204,114,0)}}
.scantime{font-family:var(--mono);font-size:10px;color:var(--text3)}

/* ── LAYOUT ── */
main{display:grid;grid-template-columns:1fr 308px;flex:1;overflow:hidden}
.left{display:flex;flex-direction:column;overflow:hidden;border-right:1px solid var(--border)}
.right{overflow-y:auto;background:var(--bg1);display:flex;flex-direction:column}

/* ── PANEL BAR ── */
.pbar{
  display:flex;align-items:center;justify-content:space-between;
  padding:10px 20px;border-bottom:1px solid var(--border);flex-shrink:0
}
.pbar-title{font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:.08em;color:var(--text3)}
.pill{
  background:var(--bg2);border:1px solid var(--border2);border-radius:20px;
  padding:2px 9px;font-family:var(--mono);font-size:11px;color:var(--text2)
}

/* ── TABLE ── */
.tscroll{flex:1;overflow:auto}
table{width:100%;border-collapse:collapse;min-width:820px}
thead{position:sticky;top:0;z-index:10;background:var(--bg1)}
th{
  padding:8px 12px;text-align:left;
  font-size:9px;font-weight:600;text-transform:uppercase;letter-spacing:.08em;
  color:var(--text3);border-bottom:1px solid var(--border);white-space:nowrap
}
th:first-child{padding-left:20px} th:last-child{padding-right:20px;text-align:right}
td{padding:0 12px;height:46px;border-bottom:1px solid rgba(26,36,56,.5);vertical-align:middle;white-space:nowrap}
td:first-child{padding-left:20px} td:last-child{padding-right:20px}
tbody tr{transition:background .1s}
tbody tr:hover{background:rgba(255,255,255,.018)}
tbody tr.tr-unknown:hover{background:var(--red-a)}
tbody tr.tr-known:hover{background:rgba(13,204,114,.03)}
tbody tr.tr-me:hover{background:var(--blue-a)}
tbody tr:last-child td{border-bottom:none}

/* status */
.sc{display:flex;align-items:center;gap:8px}
.sd{width:7px;height:7px;border-radius:50%;flex-shrink:0}
.sd.g{background:var(--green);box-shadow:0 0 7px rgba(13,204,114,.55)}
.sd.r{background:var(--red);box-shadow:0 0 7px rgba(240,67,90,.5);animation:blink 2.5s ease-in-out infinite}
.sd.b{background:var(--blue);box-shadow:0 0 7px rgba(58,175,232,.55)}
@keyframes blink{0%,100%{opacity:1}50%{opacity:.25}}
.sl{font-size:11px;font-weight:500}
.sl.g{color:var(--green)} .sl.r{color:var(--red)} .sl.b{color:var(--blue)}

/* cells */
.ipc{display:flex;align-items:center;gap:5px}
.ipv{font-family:var(--mono);font-size:12px;font-weight:500}
.macv{font-family:var(--mono);font-size:10px;color:var(--text2)}
.np{font-size:12px;font-weight:500}
.ns{font-family:var(--mono);font-size:10px;color:var(--text2);margin-top:1px}
.vv{font-size:11px;color:var(--text2);max-width:130px;overflow:hidden;text-overflow:ellipsis}
.lat{font-family:var(--mono);font-size:11px;font-weight:500}
.lat.f{color:var(--green)}.lat.m{color:var(--yellow)}.lat.s{color:var(--red)}.lat.n{color:var(--text3)}
.ports{display:flex;gap:3px}
.pc{
  padding:2px 5px;background:var(--cyan-a);border:1px solid rgba(0,217,245,.12);
  border-radius:3px;font-family:var(--mono);font-size:9px;font-weight:600;
  color:var(--cyan);letter-spacing:.02em
}
.ts{font-family:var(--mono);font-size:10px;color:var(--text3)}
.acts{display:flex;align-items:center;gap:5px;justify-content:flex-end}
.empty-row td{text-align:center;color:var(--text3);padding:52px;font-size:12px;border:none}
th.sortable{cursor:pointer;user-select:none;transition:color .15s}
th.sortable:hover{color:var(--text2)}
th.sortable.sorted{color:var(--cyan)}
.si{display:inline-block;width:8px;font-size:9px;margin-left:3px;opacity:0;transition:opacity .15s}
th.sortable.sorted .si{opacity:1}
th.sortable:hover .si{opacity:.5}

/* ── BUTTONS ── */
button{
  display:inline-flex;align-items:center;gap:4px;
  padding:5px 10px;background:transparent;
  border:1px solid var(--border2);border-radius:4px;
  color:var(--text2);font-family:var(--ui);font-size:11px;font-weight:500;
  cursor:pointer;transition:all .15s;white-space:nowrap;line-height:1
}
button:hover{background:var(--bg2);border-color:var(--border2);color:var(--text)}
.bg{border-color:rgba(13,204,114,.25);color:var(--green)}.bg:hover{background:var(--green-a);border-color:rgba(13,204,114,.4)}
.br{border-color:rgba(240,67,90,.25);color:var(--red)}.br:hover{background:var(--red-a);border-color:rgba(240,67,90,.4)}
.bb{border-color:rgba(58,175,232,.25);color:var(--blue)}.bb:hover{background:var(--blue-a);border-color:rgba(58,175,232,.4)}
.bc{border-color:rgba(0,217,245,.18);color:var(--cyan);font-size:10px;padding:4px 9px}.bc:hover{background:var(--cyan-a)}
.bico{padding:4px 6px;font-size:11px;color:var(--text3);border-color:transparent;opacity:0;transition:opacity .15s,background .15s}
tr:hover .bico{opacity:1}
.bico:hover{color:var(--text);border-color:var(--border2)!important;opacity:1}
.bico.ok{color:var(--green)!important;opacity:1}

/* ── SIDEBAR CARDS ── */
.card{border-bottom:1px solid var(--border)}
.card:last-child{border-bottom:none;flex:1}
.chead{
  display:flex;align-items:center;justify-content:space-between;
  padding:10px 14px;border-bottom:1px solid var(--border)
}
.ctitle{font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:.08em;color:var(--text3)}
.cbadge{font-family:var(--mono);font-size:11px;color:var(--text2)}
.cwrap{padding:12px 14px 14px}

/* known list */
.ki{
  display:flex;align-items:center;justify-content:space-between;
  padding:8px 14px;gap:10px;border-bottom:1px solid rgba(26,36,56,.4);
  transition:background .1s
}
.ki:last-child{border-bottom:none}
.ki:hover{background:rgba(255,255,255,.015)}
.kn{font-size:12px;font-weight:500}
.km{font-family:var(--mono);font-size:10px;color:var(--text3);margin-top:1px}
.addrow{display:flex;gap:6px;padding:8px 10px;border-top:1px solid var(--border)}
input{
  flex:1;background:var(--bg);border:1px solid var(--border2);
  border-radius:4px;color:var(--text);padding:6px 9px;
  font-family:var(--mono);font-size:11px;transition:border-color .15s;min-width:0
}
input::placeholder{color:var(--text3)}
input:focus{outline:none;border-color:var(--cyan)}
.ni{max-width:72px;font-family:var(--ui);font-size:12px}

/* hook */
.hbody{padding:10px 14px;display:flex;flex-direction:column;gap:8px}
.envrow{display:flex;flex-wrap:wrap;gap:3px}
.ev{
  padding:2px 6px;background:rgba(0,217,245,.06);border:1px solid rgba(0,217,245,.1);
  border-radius:3px;font-family:var(--mono);font-size:9px;color:rgba(0,217,245,.65)
}
textarea{
  width:100%;background:var(--bg);border:1px solid var(--border2);border-radius:4px;
  color:var(--text);padding:8px 9px;font-family:var(--mono);font-size:11px;
  line-height:1.65;resize:vertical;min-height:76px;transition:border-color .15s
}
textarea::placeholder{color:var(--text3)}
textarea:focus{outline:none;border-color:var(--cyan)}
.hhelp{font-size:11px;color:var(--text3);line-height:1.7}
</style>
</head>
<body>

<header>
  <div class="brand">
    <div class="brand-mark">📡</div>
    <span class="brand-name">NetScan</span>
  </div>
  <div class="hdiv"></div>
  <div class="hstat"><span class="hstat-l">Network</span><span class="hstat-v" id="h-net">—</span></div>
  <div class="hdiv"></div>
  <div class="hstat"><span class="hstat-l">SSID</span><span class="hstat-v" id="h-ssid">—</span></div>
  <div class="hright">
    <span class="scantime" id="h-ts"></span>
    <div class="live-pill"><span class="live-dot"></span><span id="h-count">—</span> devices</div>
  </div>
</header>

<main>
  <div class="left">
    <div class="pbar">
      <span class="pbar-title">Connected Devices</span>
      <span class="pill" id="t-count">—</span>
    </div>
    <div class="tscroll">
      <table>
        <thead>
          <tr>
            <th class="sortable" data-col="status" onclick="sortBy('status')">Status<span class="si">↑</span></th>
            <th class="sortable sorted" data-col="ip" onclick="sortBy('ip')">IP Address<span class="si">↑</span></th>
            <th class="sortable" data-col="mac" onclick="sortBy('mac')">MAC<span class="si">↑</span></th>
            <th class="sortable" data-col="vendor" onclick="sortBy('vendor')">Vendor<span class="si">↑</span></th>
            <th class="sortable" data-col="latency" onclick="sortBy('latency')">Latency<span class="si">↑</span></th>
            <th class="sortable" data-col="ports" onclick="sortBy('ports')">Ports<span class="si">↑</span></th>
            <th class="sortable" data-col="first_seen" onclick="sortBy('first_seen')">First Seen<span class="si">↑</span></th>
            <th style="text-align:right">Actions</th>
          </tr>
        </thead>
        <tbody id="tbody">
          <tr class="empty-row"><td colspan="8">Scanning network…</td></tr>
        </tbody>
      </table>
    </div>
  </div>

  <div class="right">
    <div class="card">
      <div class="chead">
        <span class="ctitle">Device History</span>
        <span class="cbadge" id="c-span">—</span>
      </div>
      <div class="cwrap"><canvas id="chart" height="110"></canvas></div>
    </div>

    <div class="card">
      <div class="chead">
        <span class="ctitle">Known Devices</span>
        <span class="cbadge" id="k-count">0</span>
      </div>
      <div id="known-list">
        <div class="ki"><span style="color:var(--text3);font-size:11px">No known devices yet</span></div>
      </div>
      <div class="addrow">
        <input id="add-mac" placeholder="MAC address">
        <input id="add-name" class="ni" placeholder="Label">
        <button class="bg" onclick="addKnown()">Add</button>
      </div>
    </div>

    <div class="card">
      <div class="chead"><span class="ctitle">Join Hook</span></div>
      <div class="hbody">
        <p class="hhelp">Shell script run when a new device joins.</p>
        <div class="envrow">
          <span class="ev">DEVICE_IP</span><span class="ev">DEVICE_MAC</span>
          <span class="ev">DEVICE_VENDOR</span><span class="ev">DEVICE_HOSTNAME</span><span class="ev">SSID</span>
        </div>
        <textarea id="hook-script" placeholder="# e.g. curl ntfy.sh/alerts -d &quot;$DEVICE_IP joined $SSID&quot;"></textarea>
        <button class="bc" id="save-btn" onclick="saveHook()">Save Hook</button>
      </div>
    </div>
  </div>
</main>

<script src="https://cdn.jsdelivr.net/npm/chart.js@4/dist/chart.umd.min.js"></script>
<script>
const PN = {22:'SSH',80:'HTTP',443:'HTTPS',554:'RTSP',8080:'ALT',8883:'MQTT',9100:'PRN',5000:'UPNP'};
let chart = null, hookLoaded = false, sortCol = 'ip', sortDir = 1, lastDevices = [];

function fmtTs(ts) {
  if (!ts) return '';
  const d = new Date(ts*1000), n = new Date();
  return d.toDateString()===n.toDateString()
    ? d.toLocaleTimeString([],{hour:'2-digit',minute:'2-digit',second:'2-digit'})
    : d.toLocaleDateString([],{month:'short',day:'numeric'})+' '+d.toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'});
}

function fmtLat(ms) {
  if (ms==null) return '<span class="lat n">—</span>';
  return '<span class="lat '+(ms<5?'f':ms<50?'m':'s')+'">'+ms+'ms</span>';
}

function sortBy(col) {
  if (sortCol === col) { sortDir *= -1; } else { sortCol = col; sortDir = 1; }
  document.querySelectorAll('th[data-col]').forEach(th => {
    const active = th.dataset.col === sortCol;
    th.classList.toggle('sorted', active);
    th.querySelector('.si').textContent = active ? (sortDir === 1 ? '↑' : '↓') : '↑';
  });
  renderDevices(lastDevices);
}

function getSorted(devices) {
  const ipNum = ip => ip.split('.').reduce((n, o) => n * 256 + +o, 0);
  return [...devices].sort((a, b) => {
    let av, bv;
    switch (sortCol) {
      case 'status':  av = a.me?0:a.is_known?1:2; bv = b.me?0:b.is_known?1:2; break;
      case 'ip':      av = ipNum(a.ip); bv = ipNum(b.ip); break;
      case 'mac':     av = a.mac; bv = b.mac; break;
      case 'vendor':  av = (a.vendor==='—'?'zzz':a.vendor||'').toLowerCase();
                      bv = (b.vendor==='—'?'zzz':b.vendor||'').toLowerCase(); break;
      case 'latency': av = a.latency??Infinity; bv = b.latency??Infinity; break;
      case 'ports':   av = (a.ports||[]).length; bv = (b.ports||[]).length; break;
      case 'first_seen': av = a.first_seen||0; bv = b.first_seen||0; break;
      default: return 0;
    }
    return av < bv ? -sortDir : av > bv ? sortDir : 0;
  });
}

function cpBtn(val) {
  return `<button class="bico" onclick="cp(this,'${val}')">⎘</button>`;
}

function cp(btn, text) {
  navigator.clipboard.writeText(text).then(()=>{
    btn.textContent='✓'; btn.classList.add('ok');
    setTimeout(()=>{btn.textContent='⎘';btn.classList.remove('ok');},1400);
  }).catch(()=>{});
}

function api(url, body) {
  return fetch(url,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)}).then(()=>refresh());
}

function wol(mac, btn) {
  fetch('/api/wol',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({mac})})
    .then(()=>{btn.textContent='Sent!';setTimeout(()=>btn.textContent='WoL',1600);});
}

function toggleKnown(mac, isKnown, hint) {
  if (isKnown) { api('/api/known/remove',{mac}); }
  else {
    const name=(prompt('Label for '+mac+':',hint||'')||'').trim();
    api('/api/known/add',{mac,name});
  }
}

function addKnown() {
  const mac=document.getElementById('add-mac').value.trim();
  const name=document.getElementById('add-name').value.trim();
  if (!mac) return;
  api('/api/known/add',{mac,name}).then(()=>{
    document.getElementById('add-mac').value='';
    document.getElementById('add-name').value='';
  });
}

function saveHook() {
  const b=document.getElementById('save-btn');
  fetch('/api/hook',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({script:document.getElementById('hook-script').value})})
    .then(()=>{b.textContent='Saved ✓';setTimeout(()=>b.textContent='Save Hook',2000);});
}

function renderDevices(devices) {
  lastDevices = devices;
  const tb=document.getElementById('tbody');
  document.getElementById('t-count').textContent=devices.length;
  document.getElementById('h-count').textContent=devices.length;
  if (!devices.length){tb.innerHTML='<tr class="empty-row"><td colspan="8">No devices detected</td></tr>';return;}
  tb.innerHTML=getSorted(devices).map(d=>{
    const isMe=d.me,isKnown=d.is_known;
    const rc=isMe?'tr-me':isKnown?'tr-known':'tr-unknown';
    const dc=isMe?'b':isKnown?'g':'r';
    const lbl=isMe?'You':isKnown?(d.known_name||'Known'):'Unknown';
    const host=(d.hostname&&d.hostname!='—')?d.hostname:'';
    const nameHtml=d.known_name
      ?'<div class="np">'+d.known_name+'</div>'+(host?'<div class="ns">'+host+'</div>':'')
      :(host?'<span class="ns" style="font-size:11px;color:var(--text2)">'+host+'</span>':'');
    const ports=(d.ports||[]).map(p=>'<span class="pc">'+(PN[p]||p)+'</span>').join('');
    const knowBtn=isMe?'':(isKnown
      ?`<button class="br" onclick="toggleKnown('${d.mac}',true,'')">Unmark</button>`
      :`<button onclick="toggleKnown('${d.mac}',false,'${(host||'').replace(/'/g,'')}')">Mark Known</button>`);
    return `<tr class="${rc}">`
      +`<td><div class="sc"><span class="sd ${dc}"></span><span class="sl ${dc}">${lbl}</span></div></td>`
      +`<td><div class="ipc"><span class="ipv">${d.ip}</span>${cpBtn(d.ip)}</div></td>`
      +`<td><span class="macv">${d.mac}</span> ${cpBtn(d.mac)}</td>`
      +`<td><span class="vv">${(()=>{
        if(d.vendor&&d.vendor!='—') return d.vendor;
        if(d.fingerprint) return `<span style="color:var(--accent);font-style:italic">${d.fingerprint}</span>`;
        return '<span style="color:var(--text3)">—</span>';
      })()}</span></td>`
      +`<td>${fmtLat(d.latency)}</td>`
      +`<td><div class="ports">${ports||'<span style="color:var(--text3);font-size:10px">—</span>'}</div></td>`
      +`<td><span class="ts">${fmtTs(d.first_seen)}</span></td>`
      +`<td><div class="acts">${knowBtn}<button class="bb" onclick="wol('${d.mac}',this)">WoL</button></div></td>`
      +`</tr>`;
  }).join('');
}

function renderKnown(known) {
  const el=document.getElementById('known-list');
  const entries=Object.entries(known);
  document.getElementById('k-count').textContent=entries.length;
  if (!entries.length){el.innerHTML='<div class="ki"><span style="color:var(--text3);font-size:11px">No known devices yet</span></div>';return;}
  el.innerHTML=entries.map(([mac,info])=>
    `<div class="ki">`
    +`<div><div class="kn">${info.name||'(unnamed)'}</div><div class="km">${mac}</div></div>`
    +`<button class="br" style="font-size:10px;padding:3px 8px" onclick="api('/api/known/remove',{mac:'${mac}'})">✕</button>`
    +`</div>`
  ).join('');
}

function updateChart(history) {
  const labels=history.map(h=>new Date(h.ts*1000).toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'}));
  const data=history.map(h=>h.count);
  if (history.length>1){
    const mins=Math.round((history[history.length-1].ts-history[0].ts)/60);
    document.getElementById('c-span').textContent=mins+'min';
  }
  if (!chart){
    chart=new Chart(document.getElementById('chart'),{
      type:'line',
      data:{labels,datasets:[{data,borderColor:'rgba(0,217,245,.65)',backgroundColor:'rgba(0,217,245,.05)',fill:true,tension:.4,pointRadius:0,borderWidth:1.5}]},
      options:{responsive:true,plugins:{legend:{display:false},tooltip:{
        backgroundColor:'rgba(12,16,24,.96)',borderColor:'rgba(0,217,245,.2)',borderWidth:1,
        titleColor:'rgba(0,217,245,.75)',bodyColor:'#D8E2F0',
        titleFont:{family:"'JetBrains Mono',monospace",size:10},
        bodyFont:{family:"'JetBrains Mono',monospace",size:11},
        callbacks:{title:i=>i[0].label,label:c=>c.raw+' devices'}
      }},
      scales:{
        x:{display:false},
        y:{min:0,border:{display:false},grid:{color:'rgba(26,36,56,.8)'},
          ticks:{color:'#374A60',font:{family:"'JetBrains Mono',monospace",size:9},stepSize:1}}
      },animation:false,interaction:{mode:'index',intersect:false}}
    });
  } else {
    chart.data.labels=labels;
    chart.data.datasets[0].data=data;
    chart.update('none');
  }
}

async function refresh() {
  try {
    const [s,h]=await Promise.all([fetch('/api/state').then(r=>r.json()),fetch('/api/history').then(r=>r.json())]);
    document.getElementById('h-ssid').textContent=s.ssid||'—';
    document.getElementById('h-net').textContent=s.network||'—';
    document.getElementById('h-ts').textContent=s.last_scan?'Updated '+s.last_scan:'';
    renderDevices(s.devices||[]);
    renderKnown(s.known||{});
    try{updateChart(h||[]);}catch(e2){}
    if (!hookLoaded&&s.hook!==undefined){document.getElementById('hook-script').value=s.hook;hookLoaded=true;}
  } catch(e){console.error(e);}
}

refresh();
setInterval(refresh,3000);
</script>
</body>
</html>
"""


class _Handler(BaseHTTPRequestHandler):
    store = None
    get_state = None       # callable → dict
    on_known_change = None # callable → triggers menu redraw

    def do_GET(self):
        if self.path == "/":
            self._send(200, "text/html", _HTML.encode())
        elif self.path == "/api/state":
            self._send(200, "application/json", json.dumps(self.get_state()).encode())
        elif self.path == "/api/history":
            self._send(200, "application/json", json.dumps(self.store.history).encode())
        else:
            self._send(404, "text/plain", b"Not found")

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(length) or b"{}")

        if self.path == "/api/known/add":
            self.store.add_known(body.get("mac", ""), body.get("name", ""))
            if self.on_known_change:
                self.on_known_change()
            self._send(200, "application/json", b'{"ok":true}')
        elif self.path == "/api/known/remove":
            self.store.remove_known(body.get("mac", ""))
            if self.on_known_change:
                self.on_known_change()
            self._send(200, "application/json", b'{"ok":true}')
        elif self.path == "/api/hook":
            self.store.set_hook_script(body.get("script", ""))
            self._send(200, "application/json", b'{"ok":true}')
        elif self.path == "/api/wol":
            try:
                from wol import wake
                wake(body.get("mac", ""))
                self._send(200, "application/json", b'{"ok":true}')
            except Exception as e:
                self._send(500, "application/json", json.dumps({"error": str(e)}).encode())
        else:
            self._send(404, "text/plain", b"Not found")

    def _send(self, code: int, ctype: str, body: bytes):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *_):
        pass


class _Server(HTTPServer):
    """HTTPServer with SO_REUSEPORT so a restarted process can bind immediately."""
    allow_reuse_address = True
    allow_reuse_port    = True


def start(store, get_state, on_known_change=None, port: int = PORT):
    _Handler.store            = store
    _Handler.get_state        = get_state
    _Handler.on_known_change  = on_known_change

    # Retry binding for up to 15 s in case the previous instance's socket is
    # still in TIME_WAIT after a rapid launchd restart.
    deadline = time.monotonic() + 15
    while True:
        try:
            server = _Server(("127.0.0.1", port), _Handler)
            break
        except OSError:
            if time.monotonic() > deadline:
                raise
            time.sleep(1)

    threading.Thread(target=server.serve_forever, daemon=True).start()
    return port
