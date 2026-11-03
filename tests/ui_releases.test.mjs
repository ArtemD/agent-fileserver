// Browser tests for the releases dashboard panel (ui/releases.html, issue #24).
// Run: node tests/ui_releases.test.mjs (needs playwright + Chromium, see ui_host.mjs).
import assert from "node:assert/strict";
import { openPanel, textResult, run, BASE, expectContentSize, expectPhoneFit, PHONES } from "./ui_host.mjs";

const DAY = 86400000;
const iso = (offsetDays) => new Date(Date.now() + offsetDays * DAY).toISOString();
const tok = (n) => String(n).padStart(22, "t");

function view(n, extra = {}) {
  return {
    token: tok(n), url: `${BASE}/${tok(n)}/`, label: "", created_at: iso(-10 + n * 0.001),
    expires_at: null, source_basename: `site${n}`, files: 1, bytes: 1000 + n, spa: false,
    protected: false, ...extra,
  };
}
function listResult(releases, extra = {}) {
  const total = releases.reduce((a, r) => a + r.bytes, 0);
  const expiring = releases.filter((r) => r.expires_at && new Date(r.expires_at) - Date.now() <= 7 * DAY).length;
  return textResult({ releases, count: releases.length, total_bytes: total, truncated: false, expiring_within_7_days: expiring, ...extra });
}

const opened = [];
async function open(result, onCall) {
  const panel = await openPanel("releases.html", { onCall });
  opened.push(panel);
  if (result) { await panel.toolResult(result); }
  return panel;
}
const names = (panel) => panel.frame.$$eval("#rows tr", (trs) => trs.map((tr) => tr.querySelector(".name").textContent));
const head = (panel) => panel.frame.textContent("#head");
const rowFor = (panel, token) => panel.frame.locator(`tr[data-token="${token}"]`);
const toolCalls = (panel) => panel.calls.filter((c) => c.name !== undefined);

const sample = () => [
  view(1, { label: "Alpha", bytes: 5000, created_at: iso(-5) }),
  view(2, { label: "Bravo", bytes: 90000, created_at: iso(-1), expires_at: iso(20) }),
  view(3, { original_filename: "report.pdf", bytes: 300, created_at: iso(-3), updated_at: iso(-0.5), expires_at: iso(3), protected: true }),
  view(4, { source_basename: "gamma-site", bytes: 20000, created_at: iso(-9), expires_at: iso(1.5) }),
  view(5, { label: "Echo", bytes: 700, created_at: iso(-7), expires_at: iso(-1) }),
];

async function finish(panel) {
  assert.deepEqual(panel.errors, []);
  await panel.close();
}

await run("ui_releases", {
  "fits a phone and can be used by touch in every state, including the delete confirmation": async () => {
    const long = "quarterly-report-final-version-without-any-spaces-at-all.pdf";
    for (const phone of PHONES) {
      const panel = await openPanel("releases.html", { phone, onCall: () => textResult({ error: "rate limited", hint: "Wait a minute, then try again." }, true) });
      opened.push(panel);
      await expectPhoneFit(panel, "waiting");
      await panel.toolResult(listResult([view(1, { label: long, protected: true, expires_at: iso(3) }), ...sample().slice(1)], { truncated: true }));
      await panel.frame.waitForSelector("#rows tr");
      await expectPhoneFit(panel, "list with a long name and the truncation note");
      await panel.frame.locator("#filter").tap();
      await panel.frame.locator("#filter").fill("zzz-no-match");
      await expectPhoneFit(panel, "filter with no match");
      await panel.frame.locator("#filter").fill("");
      const row = rowFor(panel, tok(1));
      await row.getByRole("button", { name: "Delete" }).tap();
      await row.getByRole("button", { name: "Confirm delete" }).waitFor();
      await expectPhoneFit(panel, "delete confirmation");
      await row.getByRole("button", { name: "Confirm delete" }).tap();
      await row.locator(".rowerr").waitFor();
      await expectPhoneFit(panel, "row error");
      await panel.toolResult(listResult([]));
      await expectPhoneFit(panel, "empty");
      await panel.toolResult(textResult({ error: "unauthorized", hint: "Check the key." }, true));
      await expectPhoneFit(panel, "error result");
      await finish(panel);
    }
  },

  "reports its content height, grows and shrinks with it, never resends a size": async () => {
    const panel = await open(null);
    const waiting = await expectContentSize(panel);
    await panel.toolResult(listResult(sample().slice(0, 2)));
    await panel.frame.waitForSelector("#rows tr");
    const table = await expectContentSize(panel);
    assert.ok(table.height > waiting.height, "the dashboard is taller than the waiting line");
    await panel.toolResult(textResult({ error: "unauthorized", hint: "Check the key." }, true));
    await panel.frame.waitForFunction(() => /unauthorized/.test(document.getElementById("status").textContent));
    const error = await expectContentSize(panel);
    assert.ok(error.height < table.height, "the panel reports a smaller size after its content shrinks");
    await finish(panel);
  },

  "waits for the result, then renders totals and rows": async () => {
    const panel = await open(null);
    assert.match(await panel.frame.textContent("#status"), /Waiting for the result/);
    await panel.toolResult(listResult(sample()));
    await panel.frame.waitForSelector("#rows tr");
    assert.equal(await head(panel), "5 releases · 96 KB in total · 3 expiring within 7 days".replace("96 KB", await panel.frame.evaluate((n) => window.fserver.fmtBytes(n), 5000 + 90000 + 300 + 20000 + 700 + 15)));
    assert.equal((await names(panel)).length, 5);
    assert.ok((await names(panel)).includes("report.pdf"));
    assert.ok((await names(panel)).includes("gamma-site"));
    assert.equal(await panel.frame.locator("#trunc").isVisible(), false);
    const r3 = await rowFor(panel, tok(3)).textContent();
    assert.match(r3, /Password/);
    assert.match(r3, /Updated/);
    assert.match(r3, /3 days/);
    assert.match(await rowFor(panel, tok(1)).textContent(), /Public/);
    assert.match(await rowFor(panel, tok(1)).textContent(), /Never/);
    assert.match(await rowFor(panel, tok(1)).textContent(), /Created/);
    assert.match(await rowFor(panel, tok(5)).textContent(), /Expired/);
    assert.match(await rowFor(panel, tok(2)).textContent(), /20 days/);
    assert.ok(await rowFor(panel, tok(3)).locator(".badge.warn").count());
    assert.equal(await rowFor(panel, tok(2)).locator(".badge.warn").count(), 0);
    await finish(panel);
  },

  "error result shows error and hint": async () => {
    const panel = await open(textResult({ error: "unauthorized", hint: "Check the key." }, true));
    const t = await panel.frame.textContent("#status");
    assert.match(t, /unauthorized/);
    assert.match(t, /Check the key\./);
    assert.equal(await panel.frame.locator("#main").isVisible(), false);
    await finish(panel);
  },

  "truncated note": async () => {
    const panel = await open(listResult(sample(), { truncated: true }));
    assert.equal((await panel.frame.textContent("#trunc")).trim(), "Showing the newest 1,000");
    assert.equal(await panel.frame.locator("#trunc").isVisible(), true);
    await finish(panel);
  },

  "empty list": async () => {
    const panel = await open(listResult([]));
    assert.equal((await panel.frame.textContent("#empty")).trim(), "No releases yet.");
    assert.equal(await panel.frame.locator("#empty").isVisible(), true);
    assert.match(await head(panel), /^0 releases · 0 B in total · 0 expiring within 7 days$/);
    await finish(panel);
  },

  "bare array from older servers": async () => {
    const panel = await open(textResult(sample()));
    await panel.frame.waitForSelector("#rows tr");
    assert.equal((await names(panel)).length, 5);
    assert.match(await head(panel), /^5 releases · .* in total · 3 expiring within 7 days$/);
    await finish(panel);
  },

  "at phone width each release is a card that fits the frame (issue #30)": async () => {
    const releases = sample();
    releases[0] = { ...releases[0], label: "A rather long release name that has to wrap on a phone" };
    const panel = await open(listResult(releases));
    await panel.frame.waitForSelector("#rows tr");
    // Wide frame: a table with a visible header.
    assert.equal(await panel.frame.$eval("#rows tr", (tr) => getComputedStyle(tr).display), "table-row");
    assert.ok(await panel.frame.$eval("thead th", (th) => th.getBoundingClientRect().height > 1), "header shown");
    await panel.resize(375);
    const layout = await panel.frame.evaluate(() => {
      const root = document.documentElement;
      const out = { scroll: root.scrollWidth, client: root.clientWidth, rows: [] };
      for (const tr of document.querySelectorAll("#rows tr")) {
        const row = tr.getBoundingClientRect();
        const name = tr.querySelector("td.c-name").getBoundingClientRect();
        const boxes = [...tr.querySelectorAll("td, button")].map((n) => n.getBoundingClientRect())
          .filter((b) => b.width > 0).map((b) => [Math.floor(b.left), Math.ceil(b.right)]);
        out.rows.push({ display: getComputedStyle(tr).display, rowWidth: row.width, nameWidth: name.width, boxes,
          buttons: tr.querySelectorAll("button").length, expires: getComputedStyle(tr.querySelector("td.c-exp"), "::before").content });
      }
      out.header = document.querySelector("thead").getBoundingClientRect().height;
      return out;
    });
    assert.ok(layout.scroll <= layout.client, `no sideways scroll (${layout.scroll} > ${layout.client})`);
    assert.ok(layout.header <= 1, "column header hidden visually at phone width");
    assert.equal(layout.rows.length, releases.length);
    for (const r of layout.rows) {
      assert.equal(r.display, "flex", "a row is a card");
      assert.ok(r.nameWidth >= r.rowWidth - 1, "the name spans the card");
      assert.ok(r.buttons >= 3, "the actions are there");
      assert.equal(r.expires, '"Expires "', "the expiry is labelled");
      for (const [left, right] of r.boxes) {
        assert.ok(left >= 0 && right <= layout.client, `cell or button [${left}, ${right}] inside the ${layout.client}px frame`);
      }
    }
    await expectContentSize(panel);
    // Back to a wide frame: the table returns.
    await panel.resize(760);
    assert.equal(await panel.frame.$eval("#rows tr", (tr) => getComputedStyle(tr).display), "table-row");
    await finish(panel);
  },

  "filter narrows rows case-insensitively": async () => {
    const panel = await open(listResult(sample()));
    await panel.frame.fill("#filter", "ALPHA");
    assert.deepEqual(await names(panel), ["Alpha"]);
    await panel.frame.fill("#filter", "gamma");
    assert.deepEqual(await names(panel), ["gamma-site"]);
    await panel.frame.fill("#filter", "REPORT.pdf");
    assert.deepEqual(await names(panel), ["report.pdf"]);
    await panel.frame.fill("#filter", tok(2).toUpperCase());
    assert.deepEqual(await names(panel), ["Bravo"]);
    await panel.frame.fill("#filter", "files.example.com/" + tok(5));
    assert.deepEqual(await names(panel), ["Echo"]);
    await panel.frame.fill("#filter", "nothing-matches");
    assert.deepEqual(await names(panel), []);
    assert.match(await panel.frame.textContent("#empty"), /No releases match/);
    await panel.frame.fill("#filter", "");
    assert.equal((await names(panel)).length, 5);
    await finish(panel);
  },

  "sort orders": async () => {
    const panel = await open(listResult(sample()));
    // Newest: updated_at or created_at, descending. Bravo -1d, report -0.5d (updated), report first.
    assert.deepEqual(await names(panel), ["report.pdf", "Bravo", "Alpha", "Echo", "gamma-site"].sort((a, b) => 0));
    await panel.frame.selectOption("#sort", "largest");
    assert.deepEqual(await names(panel), ["Bravo", "gamma-site", "Alpha", "Echo", "report.pdf"]);
    await panel.frame.selectOption("#sort", "expiring");
    // Expired (-1d) first, then 1.5d, 3d, 20d, never last.
    assert.deepEqual(await names(panel), ["Echo", "gamma-site", "report.pdf", "Bravo", "Alpha"]);
    await panel.frame.selectOption("#sort", "newest");
    assert.deepEqual(await names(panel), ["report.pdf", "Bravo", "Alpha", "Echo", "gamma-site"]);
    await finish(panel);
  },

  "delete needs two clicks": async () => {
    const panel = await open(listResult(sample()), (name, args) => textResult({ ok: true }));
    const row = rowFor(panel, tok(3));
    await row.getByRole("button", { name: "Delete" }).click();
    assert.equal(panel.calls.length, 0);
    assert.equal(await row.getByRole("button", { name: "Confirm delete" }).count(), 1);
    await row.getByRole("button", { name: "Confirm delete" }).click();
    await panel.frame.waitForSelector(`tr[data-token="${tok(3)}"]`, { state: "detached" });
    assert.deepEqual(panel.calls, [{ name: "delete_release", args: { token: tok(3) } }]);
    assert.equal((await names(panel)).length, 4);
    const h = await head(panel);
    assert.match(h, /^4 releases · /);
    assert.match(h, /2 expiring within 7 days$/);
    const bytes = await panel.frame.evaluate((n) => window.fserver.fmtBytes(n), 1000 * 0 + 5000 + 90000 + 20000 + 700 + 11);
    assert.ok(h.includes(bytes + " in total"), h + " vs " + bytes);
    const ctx = await panel.waitFor("ui/update-model-context");
    assert.equal(ctx[0].params.content[0].text, "Deleted release " + tok(3));
    await finish(panel);
  },

  "delete confirm reverts after 5 seconds without a call": async () => {
    const panel = await open(listResult(sample()), () => textResult({ ok: true }));
    const row = rowFor(panel, tok(1));
    await row.getByRole("button", { name: "Delete" }).click();
    assert.equal(await row.getByRole("button", { name: "Confirm delete" }).count(), 1);
    await panel.page.waitForTimeout(4000);
    assert.equal(await row.getByRole("button", { name: "Confirm delete" }).count(), 1);
    await panel.page.waitForTimeout(1500);
    assert.equal(await row.getByRole("button", { name: "Confirm delete" }).count(), 0);
    assert.equal(await row.getByRole("button", { name: "Delete" }).count(), 1);
    assert.equal(panel.calls.length, 0);
    await finish(panel);
  },

  "keep forever sends set_expiry 0 and updates the row": async () => {
    const panel = await open(listResult(sample()), (name, args) => {
      assert.equal(name, "set_expiry");
      return textResult({ ...sample()[2], expires_at: null, notice: "kept" });
    });
    const row = rowFor(panel, tok(3));
    assert.match(await row.textContent(), /3 days/);
    await row.getByRole("button", { name: "Keep forever" }).click();
    await row.getByText("Never").waitFor();
    assert.deepEqual(panel.calls, [{ name: "set_expiry", args: { token: tok(3), expires_in_days: 0 } }]);
    assert.equal(await row.getByRole("button", { name: "Keep forever" }).count(), 0);
    assert.match(await head(panel), /2 expiring within 7 days$/);
    // Releases that never expire have no Keep forever button.
    assert.equal(await rowFor(panel, tok(1)).getByRole("button", { name: "Keep forever" }).count(), 0);
    await finish(panel);
  },

  "failure shows error and hint inline and keeps the row": async () => {
    const panel = await open(listResult(sample()), () => textResult({ error: "release not found", hint: "It may already be deleted. Do not retry." }, true));
    const row = rowFor(panel, tok(2));
    await row.getByRole("button", { name: "Delete" }).click();
    await row.getByRole("button", { name: "Confirm delete" }).click();
    await row.getByText("release not found").waitFor();
    assert.match(await row.textContent(), /It may already be deleted/);
    assert.equal((await names(panel)).length, 5);
    assert.equal(await row.getByRole("button", { name: "Delete" }).isDisabled(), false);
    await finish(panel);
  },

  "buttons are disabled while a call runs": async () => {
    let release;
    const gate = new Promise((r) => { release = r; });
    const panel = await open(listResult(sample()), async () => { await gate; return textResult({ ok: true }); });
    const row = rowFor(panel, tok(2));
    await row.getByRole("button", { name: "Delete" }).click();
    await row.getByRole("button", { name: "Confirm delete" }).click();
    await panel.page.waitForTimeout(100);
    const states = await row.locator("button").evaluateAll((bs) => bs.map((b) => b.disabled));
    assert.ok(states.length >= 3 && states.every(Boolean), JSON.stringify(states));
    release();
    await panel.frame.waitForSelector(`tr[data-token="${tok(2)}"]`, { state: "detached" });
    await finish(panel);
  },

  "open and copy use the bridge": async () => {
    const panel = await open(listResult(sample()));
    const row = rowFor(panel, tok(1));
    await row.getByRole("button", { name: "Open" }).click();
    const m = await panel.waitFor("ui/open-link");
    assert.equal(m[0].params.url, `${BASE}/${tok(1)}/`);
    await panel.frame.evaluate(() => { window.__copied = []; Object.defineProperty(navigator, "clipboard", { configurable: true, value: { writeText: (t) => { window.__copied.push(t); return Promise.resolve(); } } }); });
    await row.getByRole("button", { name: "Copy" }).click();
    await row.getByRole("button", { name: "Copied" }).waitFor();
    assert.deepEqual(await panel.frame.evaluate(() => window.__copied), [`${BASE}/${tok(1)}/`]);
    await finish(panel);
  },

  "label with HTML renders as text": async () => {
    const evil = `<img src=x onerror="window.__pwned=1"><b>bold</b>`;
    const panel = await open(listResult([view(1, { label: evil })]));
    assert.deepEqual(await names(panel), [evil]);
    assert.equal(await panel.frame.locator("#rows img, #rows b").count(), 0);
    assert.equal(await panel.frame.evaluate(() => window.__pwned), undefined);
    await finish(panel);
  },

  "foreign url is withheld": async () => {
    const panel = await open(listResult([view(1, { label: "Ours" }), view(2, { label: "Theirs", url: "https://evil.example.net/x/" })]));
    const bad = rowFor(panel, tok(2));
    assert.match(await bad.textContent(), /link withheld/);
    assert.equal(await bad.getByRole("button", { name: "Open" }).count(), 0);
    assert.equal(await bad.getByRole("button", { name: "Copy" }).count(), 0);
    assert.equal(await bad.getByRole("button", { name: "Delete" }).count(), 1);
    assert.equal(await rowFor(panel, tok(1)).getByRole("button", { name: "Open" }).count(), 1);
    await finish(panel);
  },

  "renders 1,000 rows quickly": async () => {
    const many = Array.from({ length: 1000 }, (_, i) => view(i + 1, { label: `Release ${i + 1}`, expires_at: i % 3 ? iso(i % 40) : null }));
    const panel = await open(null);
    const t0 = Date.now();
    await panel.toolResult(listResult(many, { truncated: true }));
    await panel.frame.waitForFunction(() => document.querySelectorAll("#rows tr").length === 1000);
    const ms = Date.now() - t0;
    assert.ok(ms < 2000, `render took ${ms} ms`);
    const t1 = Date.now();
    await panel.frame.fill("#filter", "Release 99");
    await panel.frame.selectOption("#sort", "largest");
    assert.ok(Date.now() - t1 < 2000, "filter and sort stay quick");
    await finish(panel);
  },
});

// Close browsers left open by failed tests so the process can exit.
await Promise.all(opened.map((p) => p.close().catch(() => {})));
