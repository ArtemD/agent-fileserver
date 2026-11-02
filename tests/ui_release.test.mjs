// Browser tests for the release card panel (ui/release.html), run with
// `node tests/ui_release.test.mjs` against the mock MCP Apps host.
import assert from "node:assert/strict";
import { openPanel, textResult, run, BASE, expectContentSize } from "./ui_host.mjs";

const TOKEN = "AbCdEfGhIjKlMnOpQrStUv";
const DAY = 86400000;

function pad(x) { return (x < 10 ? "0" : "") + x; }
function fmt(iso) {
  const d = new Date(iso);
  return pad(d.getDate()) + "." + pad(d.getMonth() + 1) + "." + d.getFullYear() + " " + pad(d.getHours()) + ":" + pad(d.getMinutes());
}
function view(over = {}) {
  return {
    token: TOKEN, url: BASE + "/" + TOKEN + "/", label: "", created_at: new Date(Date.now() - 3 * DAY).toISOString(),
    expires_at: new Date(Date.now() + 20 * DAY + 3600000).toISOString(), source_basename: "site", files: 2, bytes: 1234,
    spa: false, protected: false, ...over,
  };
}

async function withPanel(opts, fn) {
  const panel = await openPanel("release.html", opts);
  try {
    await fn(panel);
    assert.deepEqual(panel.errors, [], "no console or page errors");
  } finally {
    await panel.close();
  }
}
const text = (panel) => panel.frame.locator("body").innerText();
const btn = (panel, name) => panel.frame.getByRole("button", { name, exact: true });
const waitText = (panel, s) => panel.frame.getByText(s).first().waitFor({ timeout: 5000 });

await run("ui_release", {
  "reports its content height, grows and shrinks with it, never resends a size": () => withPanel({}, async (p) => {
    const waiting = await expectContentSize(p);
    await p.toolResult(textResult(view({ label: "My site" })));
    await waitText(p, "My site");
    const card = await expectContentSize(p);
    assert.ok(card.height > waiting.height, "the card is taller than the waiting line");
    await p.notify("ui/notifications/tool-cancelled", {});
    await waitText(p, "Cancelled.");
    const cancelled = await expectContentSize(p);
    assert.ok(cancelled.height < card.height, "the panel reports a smaller size after its content shrinks");
  }),

  "waiting state before a result": () => withPanel({}, async (p) => {
    assert.match(await text(p), /Waiting for the result…/);
  }),

  "tool-cancelled shows Cancelled.": () => withPanel({}, async (p) => {
    await p.notify("ui/notifications/tool-cancelled", {});
    await waitText(p, "Cancelled.");
  }),

  "renders a public release with all fields": () => withPanel({}, async (p) => {
    const v = view({ label: "My site", updated_at: new Date().toISOString() });
    await p.toolResult(textResult(v));
    await waitText(p, "My site");
    const t = await text(p);
    assert.ok(t.includes(v.url));
    assert.ok(t.includes("Public"));
    assert.ok(t.includes("1.2 KB"));
    assert.ok(t.includes("2 files"));
    assert.ok(t.includes("Created " + fmt(v.created_at)));
    assert.ok(t.includes("Updated " + fmt(v.updated_at)));
    assert.match(t, /Expires \d\d\.\d\d\.\d{4} \d\d:\d\d \(in 21 days\)/);
    assert.equal(await p.frame.locator(".badge.warn").count(), 0, "no warn badge at 21 days");
    for (const n of ["Copy", "Open", "Keep 30 days", "Keep 1 year", "Keep forever"]) {
      assert.equal(await btn(p, n).count(), 1, n);
    }
    assert.ok(!t.includes("notice"));
  }),

  "title falls back to original filename then source basename and file count is singular": () => withPanel({}, async (p) => {
    await p.toolResult(textResult(view({ original_filename: "report.pdf", files: 1 })));
    await waitText(p, "report.pdf");
    assert.ok((await text(p)).includes("1 file") && !(await text(p)).includes("1 files"));
    await p.toolResult(textResult(view({ source_basename: "mysite" })));
    await waitText(p, "mysite");
  }),

  "notice text is not shown": () => withPanel({}, async (p) => {
    await p.toolResult(textResult(view({ notice: "Tell the user this secret model note" })));
    await waitText(p, "Public");
    assert.ok(!(await text(p)).includes("secret model note"));
  }),

  "protected release shows password badge": () => withPanel({}, async (p) => {
    await p.toolResult(textResult(view({ protected: true, username: "viewer" })));
    await waitText(p, "Password: viewer");
    assert.ok(!(await text(p)).includes("Public"));
  }),

  "never expires hides Keep forever": () => withPanel({}, async (p) => {
    await p.toolResult(textResult(view({ expires_at: null })));
    await waitText(p, "Never expires");
    assert.equal(await btn(p, "Keep forever").count(), 0);
    assert.equal(await btn(p, "Keep 30 days").count(), 1);
  }),

  "expiring soon shows a warn badge": () => withPanel({}, async (p) => {
    await p.toolResult(textResult(view({ expires_at: new Date(Date.now() + 2 * DAY).toISOString() })));
    await waitText(p, "(in 2 days)");
    assert.equal(await p.frame.locator(".badge.warn").count(), 1);
  }),

  "expired release shows Expired": () => withPanel({}, async (p) => {
    await p.toolResult(textResult(view({ expires_at: new Date(Date.now() - 2 * DAY).toISOString() })));
    await p.frame.locator(".badge.danger", { hasText: "Expired" }).waitFor();
    assert.ok(!/\(in /.test(await text(p)));
  }),

  "foreign and javascript URLs are withheld": () => withPanel({}, async (p) => {
    for (const url of ["https://files.example.com.evil/x", "javascript:alert(1)", "https://files.example.com@evil.example/x", "http://files.example.com/x"]) {
      await p.toolResult(textResult(view({ url })));
      await waitText(p, "link withheld");
      assert.equal(await btn(p, "Open").count(), 0, url);
      assert.equal(await btn(p, "Copy").count(), 0, url);
      assert.ok(!(await text(p)).includes(url), "the URL is not displayed: " + url);
      assert.equal(await p.frame.locator("a").count(), 0);
    }
    assert.equal((await p.messages("ui/open-link")).length, 0);
  }),

  "error result shows error, hint, entry and reason": () => withPanel({}, async (p) => {
    await p.toolResult(textResult({ error: "invalid path", hint: "Rename the file and retry.", entry: "a/../b", reason: "traversal" }, true));
    await waitText(p, "invalid path");
    const t = await text(p);
    assert.ok(t.includes("Rename the file and retry."));
    assert.ok(t.includes("a/../b"));
    assert.ok(t.includes("traversal"));
    assert.equal(await btn(p, "Keep 1 year").count(), 0);
  }),

  "Keep 1 year calls set_expiry, re-renders and updates model context": () => withPanel({
    onCall: (name, args) => {
      assert.equal(name, "set_expiry");
      return textResult(view({ expires_at: new Date(Date.now() + 365 * DAY).toISOString(), label: "after" }));
    },
  }, async (p) => {
    await p.toolResult(textResult(view({ label: "before" })));
    await waitText(p, "before");
    await btn(p, "Keep 1 year").click();
    await waitText(p, "Saved");
    assert.deepEqual(p.calls, [{ name: "set_expiry", args: { token: TOKEN, expires_in_days: 365 } }]);
    const t = await text(p);
    assert.ok(t.includes("after") && !t.includes("before"));
    assert.match(t, /\(in 365 days\)/);
    const ctx = await p.waitFor("ui/update-model-context");
    assert.match(ctx[0].params.content[0].text, new RegExp("^Release " + TOKEN + " now expires at \\d{4}-"));
  }),

  "Keep forever sends 0 and reports never expires in context": () => withPanel({
    onCall: () => textResult(view({ expires_at: null })),
  }, async (p) => {
    await p.toolResult(textResult(view()));
    await btn(p, "Keep forever").click();
    await waitText(p, "Never expires");
    assert.deepEqual(p.calls[0].args, { token: TOKEN, expires_in_days: 0 });
    const ctx = await p.waitFor("ui/update-model-context");
    assert.equal(ctx[0].params.content[0].text, "Release " + TOKEN + " now never expires");
    assert.equal(await btn(p, "Keep forever").count(), 0);
  }),

  "buttons are disabled while set_expiry runs": () => {
    let release;
    const gate = new Promise((r) => { release = r; });
    return withPanel({ onCall: async () => { await gate; return textResult(view({ label: "done" })); } }, async (p) => {
      await p.toolResult(textResult(view()));
      await btn(p, "Keep 30 days").click();
      await p.frame.locator("button:disabled").first().waitFor();
      for (const n of ["Keep 30 days", "Keep 1 year", "Keep forever"]) {
        assert.equal(await btn(p, n).isDisabled(), true, n);
      }
      release();
      await waitText(p, "Saved");
      assert.equal(await btn(p, "Keep 30 days").isDisabled(), false);
    });
  },

  "set_expiry error shows the hint and re-enables the buttons": () => withPanel({
    onCall: () => textResult({ error: "release not found", hint: "List releases and use a current token." }, true),
  }, async (p) => {
    await p.toolResult(textResult(view({ label: "keepme" })));
    await btn(p, "Keep 30 days").click();
    await waitText(p, "release not found");
    const t = await text(p);
    assert.ok(t.includes("List releases and use a current token."));
    assert.ok(t.includes("keepme"), "the release stays visible");
    assert.ok(!t.includes("Saved"));
    assert.equal(await btn(p, "Keep 30 days").isDisabled(), false);
    assert.equal((await p.messages("ui/update-model-context")).length, 0);
  }),

  "Open sends ui/open-link with the URL": () => withPanel({}, async (p) => {
    const v = view();
    await p.toolResult(textResult(v));
    await btn(p, "Open").click();
    const msgs = await p.waitFor("ui/open-link");
    assert.equal(msgs.length, 1);
    assert.deepEqual(msgs[0].params, { url: v.url });
  }),

  "Copy writes the URL and shows Copied": () => withPanel({}, async (p) => {
    const v = view();
    await p.toolResult(textResult(v));
    await waitText(p, "Public");
    await p.frame.evaluate(() => { window.__copied = null; Object.defineProperty(navigator, "clipboard", { configurable: true, value: { writeText: (t) => { window.__copied = t; return Promise.resolve(); } } }); });
    await btn(p, "Copy").click();
    await waitText(p, "Copied");
    assert.equal(await p.frame.evaluate(() => window.__copied), v.url);
  }),

  "failed copy selects the URL text": () => withPanel({}, async (p) => {
    const v = view();
    await p.toolResult(textResult(v));
    await waitText(p, "Public");
    await p.frame.evaluate(() => { Object.defineProperty(navigator, "clipboard", { configurable: true, value: { writeText: () => Promise.reject(new Error("denied")) } }); });
    await btn(p, "Copy").click();
    await waitText(p, "Copy failed");
    assert.ok(!(await text(p)).includes("Copied"));
    assert.equal(await p.frame.evaluate(() => String(window.getSelection())), v.url);
  }),

  "copy without a clipboard API selects the URL text": () => withPanel({}, async (p) => {
    const v = view();
    await p.toolResult(textResult(v));
    await waitText(p, "Public");
    await p.frame.evaluate(() => { Object.defineProperty(navigator, "clipboard", { configurable: true, value: undefined }); });
    await btn(p, "Copy").click();
    await waitText(p, "Copy failed");
    assert.equal(await p.frame.evaluate(() => String(window.getSelection())), v.url);
  }),

  "a label with markup is rendered as text": () => withPanel({}, async (p) => {
    const label = "<img src=x onerror=alert(1)>";
    await p.toolResult(textResult(view({ label })));
    await waitText(p, label);
    assert.equal(await p.frame.locator("img").count(), 0);
    assert.ok((await text(p)).includes(label));
  }),

  "dark theme sets data-theme": () => withPanel({ hostContext: { theme: "dark" } }, async (p) => {
    await p.toolResult(textResult(view()));
    await waitText(p, "Public");
    assert.equal(await p.frame.evaluate(() => document.documentElement.dataset.theme), "dark");
  }),

  "a flat archive without a label is titled Website, not the server temp name": () => withPanel({}, async (p) => {
    await p.toolResult(textResult(view({ label: "", original_filename: undefined, source_basename: "api-extract-123456" })));
    await waitText(p, "Website");
    assert.ok(!(await text(p)).includes("api-extract"));
    const names = await p.frame.evaluate(() => [
      fserver.releaseName({ source_basename: "site" }),
      fserver.releaseName({ label: "Demo", original_filename: "a.pdf" }),
      fserver.releaseName({ original_filename: "a.pdf", source_basename: "a.pdf" }),
    ]);
    assert.deepEqual(names, ["site", "Demo", "a.pdf"]);
  }),
});
