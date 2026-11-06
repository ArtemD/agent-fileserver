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
// PHONES are the frame widths a phone gives a panel: a small phone (320px)
// and a common one (375px). TOUCH is the smallest tap target, in CSS pixels
// (WCAG 2.5.5, Apple's 44pt), and INPUT_FONT the smallest form-control font
// size that keeps iOS from zooming the page when a field is focused.
export const PHONES = [320, 375];
export const TOUCH = 44;
export const INPUT_FONT = 16;

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
    } else if (m.method === "ui/message") {
      // MCP Apps requires an array of content blocks, like tool results.
      const p = m.params;
      if (!p || p.role !== "user" || !Array.isArray(p.content) || !p.content.length ||
          p.content.some((c) => !c || c.type !== "text" || typeof c.text !== "string")) {
        console.error("invalid ui/message params");
        send({ jsonrpc: "2.0", id: m.id, error: { code: -32602, message: "invalid ui/message params" } });
      } else {
        send({ jsonrpc: "2.0", id: m.id, result: {} });
      }
    } else if (m.id !== undefined && typeof m.method === "string") {
      send({ jsonrpc: "2.0", id: m.id, result: {} });
    }
  });
</script></body></html>`;

// openPanel launches (or reuses) a browser and returns a controller for one panel.
// onCall(name, args) returns a CallToolResult (use textResult).
// phone: a width from PHONES opens it like a phone does: a touch screen with a
// coarse pointer, a mobile viewport and the frame that wide.
export async function openPanel(file, { onCall, hostContext = { theme: "light" }, base = BASE, phone = 0 } = {}) {
  const browser = await chromium.launch();
  openBrowsers.add(browser);
  const context = await browser.newContext(phone
    ? { viewport: { width: phone, height: 800 }, isMobile: true, hasTouch: true, deviceScaleFactor: 2 }
    : {});
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
  if (phone) {
    await page.evaluate((w) => { document.getElementById("app").style.width = w + "px"; }, phone);
  }
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
    // resize sets the frame's width (a phone is about 375px), as a host does.
    resize: async (width) => {
      await page.setViewportSize({ width: Math.max(width, 320), height: FRAME.height + 100 });
      await page.evaluate((w) => { document.getElementById("app").style.width = w + "px"; }, width);
      await panel.settle();
    },
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

// phoneProblems lists what breaks on a phone in the panel as it is now: a
// sideways scroll, an element or a line of text outside the frame, a control
// smaller than TOUCH in either direction, or a form field whose font is below
// INPUT_FONT. Visually hidden elements (clipped, 1px) and the hidden file input
// are skipped; a link inside running text is exempt from the size rule, as in
// WCAG 2.5.8. An empty list means the panel passes.
export function phoneProblems(panel) {
  return panel.frame.evaluate(({ TOUCH, INPUT_FONT }) => {
    const out = [];
    const root = document.documentElement;
    const width = root.clientWidth;
    const name = (n) => n.tagName.toLowerCase() + (n.id ? "#" + n.id : "") +
      (n.className && typeof n.className === "string" ? "." + n.className.trim().split(/\s+/).join(".") : "") +
      ' "' + (n.textContent || n.getAttribute("aria-label") || "").trim().slice(0, 30) + '"';
    const shown = (n) => {
      for (let x = n; x && x !== document.body; x = x.parentElement) {
        const cs = getComputedStyle(x);
        if (cs.display === "none" || cs.visibility === "hidden" || x.hidden) return false;
        if (cs.clip !== "auto" && cs.position === "absolute") return false;
      }
      const r = n.getBoundingClientRect();
      return r.width > 1 && r.height > 1;
    };
    if (root.scrollWidth > width) out.push(`page scrolls sideways: ${root.scrollWidth}px wide in a ${width}px frame`);
    for (const n of document.body.querySelectorAll("*")) {
      if (n.tagName === "SCRIPT" || n.tagName === "STYLE" || !shown(n)) continue;
      const r = n.getBoundingClientRect();
      if (r.left < -0.5 || r.right > width + 0.5) out.push(`${name(n)} is outside the frame (${Math.round(r.left)}..${Math.round(r.right)} of ${width})`);
      const control = n.matches("button, select, textarea, input:not([type=hidden]):not([type=checkbox]):not([type=radio]), [role=button], label.check") ||
        (n.tagName === "A" && !n.closest("p, li, .mono, .url, .muted, .hint"));
      if (control && (r.height < TOUCH - 0.5 || r.width < TOUCH - 0.5)) {
        out.push(`${name(n)} is ${Math.round(r.width)}x${Math.round(r.height)}, below the ${TOUCH}px tap target`);
      }
      if (n.matches("select, textarea, input:not([type=checkbox]):not([type=radio])") && parseFloat(getComputedStyle(n).fontSize) < INPUT_FONT) {
        out.push(`${name(n)} has a ${getComputedStyle(n).fontSize} font; iOS zooms in below ${INPUT_FONT}px`);
      }
    }
    const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
    for (let t = walker.nextNode(); t; t = walker.nextNode()) {
      if (!t.textContent.trim() || !t.parentElement || !shown(t.parentElement)) continue;
      const range = document.createRange();
      range.selectNodeContents(t);
      for (const r of range.getClientRects()) {
        if (r.right > width + 0.5) { out.push(`text "${t.textContent.trim().slice(0, 30)}" runs past the frame edge (${Math.round(r.right)} of ${width})`); break; }
      }
    }
    return out;
  }, { TOUCH, INPUT_FONT });
}

// expectPhoneFit asserts phoneProblems is empty, with what to fix if not.
export async function expectPhoneFit(panel, state) {
  await panel.settle();
  const problems = await phoneProblems(panel);
  assert.deepEqual(problems, [], `${state} at ${await panel.frame.evaluate(() => document.documentElement.clientWidth)}px`);
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
