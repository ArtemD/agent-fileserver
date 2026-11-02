// fserver bridge: a minimal MCP Apps client (protocol 2026-01-26) over
// postMessage, shared by every panel. The server inlines this file into each
// panel and replaces the base URL marker with the configured base URL.
// Rules every panel follows: render tool data as text nodes only (never parse
// it as markup), and accept a URL only when fserver.safeURL() says it is ours.
(function () {
  "use strict";
  var BASE = "__FSERVER_BASE_URL__";
  var PROTOCOL = "2026-01-26";
  var nextId = 1;
  var pending = {};
  var handlers = { "tool-input": [], "tool-result": [], "tool-cancelled": [], "context": [] };

  function post(msg) { window.parent.postMessage(msg, "*"); }
  function request(method, params) {
    var id = nextId++;
    return new Promise(function (resolve, reject) {
      pending[id] = { resolve: resolve, reject: reject };
      post({ jsonrpc: "2.0", id: id, method: method, params: params || {} });
    });
  }
  function notify(method, params) { post({ jsonrpc: "2.0", method: method, params: params || {} }); }
  function emit(kind, value) { handlers[kind].forEach(function (cb) { try { cb(value); } catch (e) { console.error(e); } }); }

  function applyContext(ctx) {
    if (!ctx || typeof ctx !== "object") { return; }
    fserver.hostContext = Object.assign({}, fserver.hostContext, ctx);
    var root = document.documentElement;
    if (ctx.theme === "light" || ctx.theme === "dark") { root.dataset.theme = ctx.theme; }
    var vars = ctx.styles && ctx.styles.variables;
    if (vars && typeof vars === "object") {
      Object.keys(vars).forEach(function (k) {
        if (/^--[a-z0-9-]+$/.test(k) && typeof vars[k] === "string") { root.style.setProperty(k, vars[k]); }
      });
    }
    emit("context", fserver.hostContext);
  }

  window.addEventListener("message", function (event) {
    if (event.source !== window.parent) { return; }
    var msg = event.data;
    if (!msg || msg.jsonrpc !== "2.0") { return; }
    if (msg.method === undefined && msg.id !== undefined && pending[msg.id]) {
      var p = pending[msg.id];
      delete pending[msg.id];
      if (msg.error) { p.reject(new Error(msg.error.message || "host error")); } else { p.resolve(msg.result); }
      return;
    }
    if (typeof msg.method !== "string") { return; }
    if (msg.id !== undefined) {
      // Host requests: teardown and ping need an empty result.
      if (msg.method === "ui/resource-teardown" || msg.method === "ping") {
        post({ jsonrpc: "2.0", id: msg.id, result: {} });
      } else {
        post({ jsonrpc: "2.0", id: msg.id, error: { code: -32601, message: "method not found" } });
      }
      return;
    }
    var params = msg.params || {};
    switch (msg.method) {
      case "ui/notifications/tool-input": emit("tool-input", params.arguments || {}); break;
      case "ui/notifications/tool-result": emit("tool-result", params); break;
      case "ui/notifications/tool-cancelled": emit("tool-cancelled", params); break;
      case "ui/notifications/host-context-changed": applyContext(params); break;
    }
  });

  var fserver = window.fserver = {
    base: BASE,
    hostContext: {},
    ready: null,
    onToolInput: function (cb) { handlers["tool-input"].push(cb); },
    onToolResult: function (cb) { handlers["tool-result"].push(cb); },
    onToolCancelled: function (cb) { handlers["tool-cancelled"].push(cb); },
    onContext: function (cb) { handlers["context"].push(cb); },

    // parseResult turns a CallToolResult into {data, isError}. This server
    // returns exactly one JSON text item; anything else is an error.
    parseResult: function (r) {
      var data = null;
      try {
        var item = r && r.content && r.content[0];
        if (item && item.type === "text") { data = JSON.parse(item.text); }
      } catch (e) { data = null; }
      if (data === null || typeof data !== "object") {
        return { data: { error: "unreadable tool result" }, isError: true };
      }
      return { data: data, isError: !!(r.isError || data.error) };
    },
    // call runs one of this server's tools through the host.
    call: function (name, args) {
      return request("tools/call", { name: name, arguments: args || {} }).then(fserver.parseResult);
    },
    // safeURL accepts only absolute URLs under the configured base URL.
    safeURL: function (u) {
      return typeof u === "string" && u.indexOf(BASE + "/") === 0 && !/[\s"'<>\\]/.test(u);
    },
    openLink: function (u) {
      if (!fserver.safeURL(u)) { return Promise.reject(new Error("refusing a URL outside " + BASE)); }
      return request("ui/open-link", { url: u });
    },
    // message posts a user-visible chat message; context updates what the
    // model knows without a message. Both are best effort.
    message: function (text) {
      return request("ui/message", { role: "user", content: { type: "text", text: String(text) } }).catch(function () {});
    },
    updateContext: function (text) {
      return request("ui/update-model-context", { content: [{ type: "text", text: String(text) }] }).catch(function () {});
    },
    resize: function () {
      var b = document.documentElement.getBoundingClientRect();
      notify("ui/notifications/size-changed", { width: Math.ceil(b.width), height: Math.ceil(document.documentElement.scrollHeight) });
    },
    copy: function (text) {
      if (navigator.clipboard && navigator.clipboard.writeText) {
        return navigator.clipboard.writeText(text).then(function () { return true; }, function () { return false; });
      }
      return Promise.resolve(false);
    },
    // el builds DOM safely: strings become text nodes, attributes are set
    // with setAttribute, and href/src values must pass safeURL.
    el: function (tag, attrs) {
      var node = document.createElement(tag);
      Object.keys(attrs || {}).forEach(function (k) {
        var v = attrs[k];
        if (v === null || v === undefined || v === false) { return; }
        if (k.indexOf("on") === 0 && typeof v === "function") { node.addEventListener(k.slice(2), v); return; }
        if ((k === "href" || k === "src") && !fserver.safeURL(v)) { return; }
        node.setAttribute(k, v === true ? "" : String(v));
      });
      for (var i = 2; i < arguments.length; i++) {
        var c = arguments[i];
        if (c === null || c === undefined || c === false) { continue; }
        node.appendChild(typeof c === "object" ? c : document.createTextNode(String(c)));
      }
      return node;
    },
    fmtBytes: function (n) {
      if (typeof n !== "number" || !isFinite(n) || n < 0) { return "?"; }
      var units = ["B", "KB", "MB", "GB", "TB"];
      var i = 0;
      while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
      return (i === 0 ? String(n) : n.toFixed(n < 10 ? 1 : 0)) + " " + units[i];
    },
    // fmtDate: dd.mm.yyyy hh:mm in the viewer's time zone.
    fmtDate: function (iso) {
      var d = new Date(iso);
      if (!iso || isNaN(d.getTime())) { return ""; }
      function p(x) { return (x < 10 ? "0" : "") + x; }
      return p(d.getDate()) + "." + p(d.getMonth() + 1) + "." + d.getFullYear() + " " + p(d.getHours()) + ":" + p(d.getMinutes());
    },
    // releaseName: label, else the published file name, else the archive's
    // wrapper folder. A flat archive's source name is a server temp name
    // (api-extract-…), which says nothing to a person, so it reads "Website".
    releaseName: function (v) {
      if (!v) { return ""; }
      if (v.label) { return String(v.label); }
      if (v.original_filename) { return String(v.original_filename); }
      if (v.source_basename && !/^api-extract-/.test(v.source_basename)) { return String(v.source_basename); }
      return "Website";
    },
    // daysLeft: whole days until iso (ceil), or null for no expiry.
    daysLeft: function (iso, now) {
      if (!iso) { return null; }
      var t = new Date(iso).getTime();
      if (isNaN(t)) { return null; }
      return Math.ceil((t - (now || Date.now())) / 86400000);
    }
  };

  fserver.ready = request("ui/initialize", {
    protocolVersion: PROTOCOL,
    appInfo: { name: "agent-fileserver", version: "1" },
    appCapabilities: {}
  }).then(function (result) {
    applyContext(result && result.hostContext);
    notify("ui/notifications/initialized", {});
    fserver.resize();
    return result;
  });
  if (window.ResizeObserver) {
    new ResizeObserver(function () { fserver.resize(); }).observe(document.documentElement);
  }
})();
