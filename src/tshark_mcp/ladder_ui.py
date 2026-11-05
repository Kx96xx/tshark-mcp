"""The MCP Apps view of ``call_ladder``: one static, self-contained HTML page.

A host that supports MCP Apps (the ``io.modelcontextprotocol/ui`` extension) renders the
page for a ``call_ladder`` result: it reads the tool result the host posts to it and draws
the arrows as an SVG ladder; hovering shows an arrow's fields, clicking asks the host to call
``packet_detail`` for that frame on this server. Hosts without Apps ignore the page and show
the Mermaid or text diagram.

Safety: no network (the Content-Security-Policy forbids connect, img and font sources), no
external script, and every packet string is set with ``textContent`` (never parsed as HTML).
"""

from __future__ import annotations

URI = "ui://tshark-mcp/ladder.html"
MIME_TYPE = "text/html;profile=mcp-app"

HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'">
<title>Call ladder</title>
<style>
  :root { --bg: #ffffff; --fg: #1d2330; --muted: #6b7280; --line: #9aa3b2; --fail: #c62828; --failbg: #fde8e6; --hl: #1e5bd8; }
  @media (prefers-color-scheme: dark) { :root { --bg: #14171c; --fg: #e6e9ef; --muted: #9aa3b2; --line: #5d6675; --fail: #ff7b72; --failbg: #3a1d1d; --hl: #7aa7ff; } }
  body { margin: 0; padding: 12px 16px; background: var(--bg); color: var(--fg); font: 13px/1.4 system-ui, sans-serif; }
  #wrap { overflow-x: auto; }
  svg text { fill: var(--fg); font: 12px ui-monospace, monospace; }
  .life { stroke: var(--line); stroke-dasharray: 4 4; }
  .arrow { stroke: var(--fg); stroke-width: 1.4; fill: none; cursor: pointer; }
  .arrow.answer { stroke-dasharray: 5 3; }
  .failed .arrow { stroke: var(--fail); }
  .failed text { fill: var(--fail); }
  .row:hover .arrow { stroke: var(--hl); stroke-width: 2.4; }
  #tip { position: fixed; display: none; background: var(--bg); border: 1px solid var(--line); padding: 6px 8px; white-space: pre; font: 12px ui-monospace, monospace; }
  #status { color: var(--muted); margin-bottom: 8px; }
</style>
</head>
<body>
<div id="status">Waiting for a call_ladder result.</div>
<div id="wrap"></div>
<div id="tip"></div>
<script type="application/json" id="data"></script>
<script>
(function () {
  "use strict";
  var NS = "http://www.w3.org/2000/svg", nextId = 1, current = null;
  function el(name, attrs, text) {
    var e = document.createElementNS(NS, name);
    Object.keys(attrs || {}).forEach(function (k) { e.setAttribute(k, String(attrs[k])); });
    if (text !== undefined) e.textContent = String(text);
    return e;
  }
  function send(method, params, isRequest) {
    var msg = { jsonrpc: "2.0", method: method, params: params || {} };
    if (isRequest) msg.id = nextId++;
    window.parent.postMessage(msg, "*");
  }
  function render(result) {
    var data = result && (result.structuredContent || result.structured_content || result);
    if (!data || !Array.isArray(data.arrows) || !Array.isArray(data.participants)) return;
    current = data;
    var parts = data.participants, arrows = data.arrows, gap = 190, top = 46, step = 30;
    var x = {}; parts.forEach(function (p, i) { x[p.address] = 90 + i * gap; });
    var width = 180 + (parts.length - 1) * gap, height = top + arrows.length * step + 30;
    var svg = el("svg", { width: width, height: height, viewBox: "0 0 " + width + " " + height, role: "img" });
    parts.forEach(function (p) {
      var cx = x[p.address];
      svg.appendChild(el("text", { x: cx, y: 16, "text-anchor": "middle" }, p.role || ""));
      svg.appendChild(el("text", { x: cx, y: 32, "text-anchor": "middle" }, p.address));
      svg.appendChild(el("line", { class: "life", x1: cx, y1: 38, x2: cx, y2: height - 6 }));
    });
    arrows.forEach(function (a, i) {
      var y = top + i * step, x1 = x[a.src], x2 = x[a.dst];
      if (x1 === undefined || x2 === undefined) return;
      var g = el("g", { class: "row" + (a.failed ? " failed" : "") });
      var dir = x2 >= x1 ? 1 : -1;
      g.appendChild(el("line", { class: "arrow" + (a.kind === "request" ? "" : " answer"), x1: x1, y1: y, x2: x2 - dir * 6, y2: y }));
      g.appendChild(el("path", { class: "arrow", d: "M" + (x2 - dir * 8) + " " + (y - 4) + " L" + x2 + " " + y + " L" + (x2 - dir * 8) + " " + (y + 4) }));
      g.appendChild(el("text", { x: (x1 + x2) / 2, y: y - 5, "text-anchor": "middle" }, "#" + a.frame + " " + a.label));
      g.addEventListener("mousemove", function (ev) {
        var tip = document.getElementById("tip");
        tip.textContent = JSON.stringify(a, null, 1);
        tip.style.display = "block"; tip.style.left = (ev.clientX + 12) + "px"; tip.style.top = (ev.clientY + 12) + "px";
      });
      g.addEventListener("mouseleave", function () { document.getElementById("tip").style.display = "none"; });
      g.addEventListener("click", function () {
        if (current && current.path) send("tools/call", { name: "packet_detail", arguments: { path: current.path, frame: a.frame } }, true);
      });
      svg.appendChild(g);
    });
    var wrap = document.getElementById("wrap");
    while (wrap.firstChild) wrap.removeChild(wrap.firstChild);
    wrap.appendChild(svg);
    document.getElementById("status").textContent =
      arrows.length + " messages, " + parts.length + " participants" + (data.rows_dropped ? ", " + data.rows_dropped + " not shown" : "") +
      ". Click an arrow to open that frame.";
  }
  window.addEventListener("message", function (ev) {
    var m = ev.data;
    if (!m || m.jsonrpc !== "2.0") return;
    if (m.method === "ui/notifications/tool-result") render(m.params);
  });
  var embedded = document.getElementById("data").textContent.trim();
  if (embedded) { try { render(JSON.parse(embedded)); } catch (e) { document.getElementById("status").textContent = "Bad embedded data."; } }
  send("ui/initialize", { appInfo: { name: "tshark-mcp ladder", version: "1" }, appCapabilities: {} }, true);
})();
</script>
</body>
</html>
"""
