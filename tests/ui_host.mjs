// Shared mock MCP Apps host for the panel browser tests (tests/ui_*.test.mjs).
// It composes a panel exactly like ui.go (bridge and base styles inlined, base
// URL marker replaced), loads it into a sandboxed iframe with an opaque origin
// (as a real host's sandbox would), answers ui/initialize, records every
// message the panel sends, and routes tools/call to a test-supplied function.
// Needs the playwright package (NODE_PATH or a local install) and Chromium.
import { createRequire } from "node:module";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import assert from "node:assert/strict";

const require = createRequire(import.meta.url);
const { chromium } = require("playwright");
const UI = join(dirname(fileURLToPath(import.meta.url)), "..", "ui");

export const BASE = "https://files.example.com";
// FRAME is the panel iframe's size: taller than any panel's first view, so a
// panel that reported the frame instead of its content would show up.
export const FRAME = { width: 760, height: 900 };

// Every browser a test opens, so run() can close them even when a test throws.
const openBrowsers = new Set();

// compose mirrors uiComposePanel in ui.go.
export function compose(file, base = BASE) {
  const page = readFileSync(join(UI, file), "utf8");
  const bridge = readFileSync(join(UI, "bridge.js"), "utf8");
  const css = readFileSync(join(UI, "base.css"), "utf8");
  const marker = '"__FSERVER_BASE_URL__"';
  assert.equal(bridge.split(marker).length, 2, "bridge base URL marker");
  assert.equal(page.split("/*FSERVER:BRIDGE*/").length, 2, file + " bridge marker");
  assert.equal(page.split("/*FSERVER:BASE_CSS*/").length, 2, file + " style marker");
  return page
    .replace("/*FSERVER:BASE_CSS*/", () => css)
    .replace("/*FSERVER:BRIDGE*/", () => bridge.replace(marker, () => JSON.stringify(base)));
}

// textResult builds a CallToolResult the way this server does: one JSON text item.
export function textResult(value, isError = false) {
  return { content: [{ type: "text", text: JSON.stringify(value) }], isError };
}

const HOST_PAGE = `<!doctype html><html><body style="margin:0">
<iframe id="app" sandbox="allow-scripts allow-forms" style="width:${FRAME.width}px;height:${FRAME.height}px;border:0"></iframe>
<script>
  window.__msgs = [];
  const frame = document.getElementById("app");
  function send(msg) { frame.contentWindow.postMessage(msg, "*"); }
  window.__send = send;
  window.addEventListener("message", async (e) => {
    if (e.source !== frame.contentWindow) return;
    const m = e.data;
    window.__msgs.push(m);
    if (m.method === "ui/initialize") {
      send({ jsonrpc: "2.0", id: m.id, result: { protocolVersion: "2026-01-26",
        hostInfo: { name: "mock-host", version: "1" }, hostCapabilities: {},
        hostContext: window.__hostContext } });
    } else if (m.method === "tools/call") {
      const result = await window.__hostCall(m.params.name, m.params.arguments || {});
      send({ jsonrpc: "2.0", id: m.id, result });
    } else if (m.id !== undefined && typeof m.method === "string") {
      send({ jsonrpc: "2.0", id: m.id, result: {} });
    }
  });
</script></body></html>`;

// openPanel launches (or reuses) a browser and returns a controller for one panel.
// onCall(name, args) returns a CallToolResult (use textResult).
export async function openPanel(file, { onCall, hostContext = { theme: "light" }, base = BASE } = {}) {
  const browser = await chromium.launch();
  openBrowsers.add(browser);
  const context = await browser.newContext();
  const page = await context.newPage();
  const errors = [];
  page.on("pageerror", (e) => errors.push(String(e)));
  page.on("console", (m) => { if (m.type() === "error") errors.push(m.text()); });
  const calls = [];
  await page.exposeFunction("__hostCall", async (name, args) => {
    calls.push({ name, args });
    if (!onCall) return textResult({ error: "no tool handler in test" }, true);
    return onCall(name, args);
  });
  await page.setContent(HOST_PAGE);
  await page.evaluate((ctx) => { window.__hostContext = ctx; }, hostContext);
  const html = compose(file, base);
  await page.evaluate((h) => { document.getElementById("app").srcdoc = h; }, html);
  const frame = await (await page.waitForSelector("#app")).contentFrame();
  const panel = {
    browser, page, frame, calls, errors, html,
    messages: (method) => page.evaluate((m) => window.__msgs.filter((x) => !m || x.method === m), method),
    waitFor: async (method, timeout = 5000) => {
      const end = Date.now() + timeout;
      for (;;) {
        const found = await panel.messages(method);
        if (found.length) return found;
        if (Date.now() > end) throw new Error("timed out waiting for " + method);
        await page.waitForTimeout(25);
      }
    },
    notify: (method, params) => page.evaluate(([m, p]) => window.__send({ jsonrpc: "2.0", method: m, params: p }), [method, params]),
    // initialized waits for the panel's handshake to finish.
    initialized: () => panel.waitFor("ui/notifications/initialized"),
    toolInput: (args) => panel.notify("ui/notifications/tool-input", { arguments: args }),
    toolResult: (result) => panel.notify("ui/notifications/tool-result", result),
    // sizes lists every size-changed report; settle waits two animation frames
    // in the panel (a report is measured in one) plus the postMessage hop.
    sizes: async () => (await panel.messages("ui/notifications/size-changed")).map((m) => m.params),
    settle: async () => {
      await frame.evaluate(() => new Promise((r) => requestAnimationFrame(() => requestAnimationFrame(r))));
      await page.waitForTimeout(50);
    },
    // contentSize is what the panel should report: its rendered content box.
    contentSize: () => frame.evaluate(() => {
      const b = document.body.getBoundingClientRect();
      return { width: Math.ceil(b.width), height: Math.ceil(b.height) };
    }),
    close: () => { openBrowsers.delete(browser); return browser.close(); },
  };
  await panel.initialized();
  return panel;
}

// expectContentSize checks the panel's last size report against its content:
// it matches the content box, is shorter than the frame (so a host can shrink
// the frame), came after the handshake, and is not resent while nothing changes.
export async function expectContentSize(panel) {
  await panel.settle();
  const sizes = await panel.sizes();
  assert.ok(sizes.length > 0, "a size was reported");
  const last = sizes[sizes.length - 1];
  assert.ok(last.height < FRAME.height, `height ${last.height} is below the ${FRAME.height}px frame`);
  assert.deepEqual(last, await panel.contentSize(), "last report is the content size");
  const all = await panel.messages();
  const init = all.findIndex((m) => m.method === "ui/notifications/initialized");
  const first = all.findIndex((m) => m.method === "ui/notifications/size-changed");
  assert.ok(init >= 0 && first > init, "no size report before initialized");
  for (let i = 1; i < sizes.length; i++) {
    assert.notDeepEqual(sizes[i], sizes[i - 1], "an identical size is never sent twice in a row");
  }
  await panel.frame.evaluate(() => { for (let i = 0; i < 5; i++) { window.fserver.resize(); } });
  await panel.settle();
  assert.equal((await panel.sizes()).length, sizes.length, "resize() with nothing changed sends nothing");
  return last;
}

// run executes named async tests sequentially and exits non-zero on failure.
export async function run(name, tests) {
  let failed = 0;
  for (const [title, fn] of Object.entries(tests)) {
    try {
      await fn();
      console.log("PASS " + name + ": " + title);
    } catch (e) {
      failed++;
      console.log("FAIL " + name + ": " + title + "\n  " + (e && e.stack || e));
    } finally {
      for (const b of openBrowsers) { await b.close().catch(() => {}); }
      openBrowsers.clear();
    }
  }
  if (failed) { process.exitCode = 1; }
}
