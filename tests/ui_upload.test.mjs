// Browser tests for the upload panel (ui/upload.html, tool upload_from_computer).
// Run: node tests/ui_upload.test.mjs  (needs playwright + Chromium, see ui_host.mjs)
import assert from "node:assert/strict";
import { createHash, randomBytes } from "node:crypto";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { openPanel, textResult, run, BASE, expectContentSize, expectPhoneFit, PHONES } from "./ui_host.mjs";

const tmp = mkdtempSync(join(tmpdir(), "ui-upload-"));
const sha = (b) => createHash("sha256").update(b).digest("hex");
const MAX = 50 * 1024 * 1024;
const PASSWORD = "correct-horse-battery";
const TOKEN22 = "AbCdEfGhIjKlMnOpQrStUv";

function makeFile(name, bytes) {
  const p = join(tmp, name);
  writeFileSync(p, bytes);
  return p;
}

// setup opens the panel with a mock begin_upload and a mock PUT endpoint.
async function setup({ begin, put, max = MAX, options, phone = 0 } = {}) {
  const begins = [];
  let n = 0;
  const panel = await openPanel("upload.html", {
    phone,
    onCall(name, args) {
      begins.push({ name, args });
      if (begin) return begin(args, ++n);
      n++;
      return textResult({
        upload_url: BASE + "/_upload", method: "PUT",
        headers: { Authorization: "Bearer upl_TICKET" + n + "_" + "x".repeat(30) },
        expires_at: new Date(Date.now() + 1800e3).toISOString(), size: args.size, sha256: args.sha256,
        command: "curl -T FILE -H 'Authorization: Bearer upl_TICKET" + n + "' " + BASE + "/_upload",
      });
    },
  });
  const puts = [];
  const cors = { "Access-Control-Allow-Origin": "*" };
  await panel.page.route(BASE + "/_upload", async (route) => {
    const req = route.request();
    if (req.method() === "OPTIONS") {
      return route.fulfill({ status: 204, headers: { ...cors, "Access-Control-Allow-Methods": "PUT", "Access-Control-Allow-Headers": "Authorization, Content-Type" } });
    }
    // Chromium exposes neither a File body (request.postData()) nor Content-Length
    // to the route, so the bytes are checked through the XHR hook installed below;
    // the route sees the method and headers.
    const h = await req.allHeaders();
    puts.push({ method: req.method(), auth: h["authorization"], ct: h["content-type"] });
    const r = put ? put(puts.length) : { status: 201, json: releaseView() };
    if (r.abort) return route.abort("failed");
    if (r.hang) return; // never answered: the upload stays in flight
    return route.fulfill({ status: r.status, headers: { ...cors, "Content-Type": "application/json" }, body: JSON.stringify(r.json) });
  });
  if (options !== null) await panel.toolInput(options || {});
  await panel.toolResult(textResult({ status: "upload panel shown", max_bytes: max }));
  await panel.frame.waitForSelector("#drop");
  // Record every body handed to XMLHttpRequest.send (File name, size, bytes).
  await panel.frame.evaluate(() => {
    const orig = XMLHttpRequest.prototype.send;
    window.__sent = [];
    XMLHttpRequest.prototype.send = function (body) {
      if (body instanceof Blob) {
        window.__sent.push(body.arrayBuffer().then((ab) => {
          let bin = "";
          const u8 = new Uint8Array(ab);
          for (let i = 0; i < u8.length; i += 8192) bin += String.fromCharCode.apply(null, u8.subarray(i, i + 8192));
          return { isFile: body instanceof File, name: body.name, size: body.size, b64: btoa(bin) };
        }));
      } else window.__sent.push(Promise.resolve({ isFile: false, other: typeof body }));
      return orig.call(this, body);
    };
  });
  const sent = async () => (await panel.frame.evaluate(() => Promise.all(window.__sent))).map((x) => ({ ...x, bytes: Buffer.from(x.b64 || "", "base64") }));
  return { panel, begins, puts, sent };
}

function releaseView(extra = {}) {
  return {
    token: TOKEN22, url: BASE + "/" + TOKEN22 + "/", label: "", created_at: new Date().toISOString(),
    expires_at: new Date(Date.now() + 7 * 86400e3 - 3600e3).toISOString(), source_basename: "site.zip",
    files: 2, bytes: 1234, spa: false, protected: false, ...extra,
  };
}

const publishBtn = (f) => f.getByRole("button", { name: "Publish", exact: true });
const text = (f) => f.evaluate(() => document.body.innerText);

async function pick(t, path) {
  await t.panel.frame.setInputFiles("input[type=file]", path);
}

async function finish(t) {
  assert.deepEqual(t.panel.errors, [], "no console or page errors");
  await t.panel.close();
}

const zipBytes = randomBytes(5000);
const tests = {
  "reports its content height and never resends a size": async () => {
    const t = await setup();
    await expectContentSize(t.panel);
    await finish(t);
  },

  "sha256 matches node:crypto for empty, abc and 9 MiB random": async () => {
    const t = await setup();
    const big = randomBytes(9 * 1024 * 1024);
    const f = t.panel.frame;
    const cases = [Buffer.alloc(0), Buffer.from("abc"), Buffer.from("a".repeat(1000)), big];
    for (const buf of cases) {
      const got = await f.evaluate(async (b64) => {
        const bin = atob(b64);
        const u8 = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);
        const fromBuf = await window.fsSha256Hex(u8.buffer);
        const fromBlob = await window.fsSha256Hex(new Blob([u8]));
        return [fromBuf, fromBlob];
      }, buf.toString("base64"));
      assert.equal(got[0], sha(buf), "ArrayBuffer hash, length " + buf.length);
      assert.equal(got[1], sha(buf), "Blob hash, length " + buf.length);
    }
    // Block boundaries around the padding rules.
    for (const n of [55, 56, 63, 64, 65, 119, 120]) {
      const buf = randomBytes(n);
      const got = await f.evaluate(async (b64) => {
        const bin = atob(b64);
        const u8 = new Uint8Array(bin.length);
        for (let i = 0; i < bin.length; i++) u8[i] = bin.charCodeAt(i);
        return window.fsSha256Hex(u8);
      }, buf.toString("base64"));
      assert.equal(got, sha(buf), "length " + n);
    }
    await finish(t);
  },

  "site.zip sends begin_upload without filename, with tool-input options, then PUT": async () => {
    const t = await setup({
      options: { label: "Demo", password: PASSWORD, expires_in_days: 7, token: TOKEN22, spa: true },
      put: () => ({ status: 201, json: releaseView({ protected: true, username: "viewer" }) }),
    });
    const f = t.panel.frame;
    const initial = await text(f);
    assert.match(initial, /Password protected/);
    assert.match(initial, new RegExp("Updates release " + TOKEN22));
    assert.ok(!initial.includes(PASSWORD), "password is not displayed");
    await pick(t, makeFile("site.zip", zipBytes));
    await f.getByLabel("Publish as one file").waitFor();
    assert.equal(t.begins.length, 0, "nothing is sent before Publish");
    await publishBtn(f).click();
    await f.waitForSelector("#result");
    assert.equal(t.begins.length, 1);
    const b = t.begins[0];
    assert.equal(b.name, "begin_upload");
    assert.equal(b.args.size, zipBytes.length);
    assert.equal(b.args.sha256, sha(zipBytes));
    assert.match(b.args.idempotency_key, /^upl-[0-9a-f]{32}$/);
    assert.ok(!("filename" in b.args), "archive publish sends no filename");
    assert.equal(b.args.label, "Demo");
    assert.equal(b.args.password, PASSWORD);
    assert.equal(b.args.expires_in_days, 7);
    assert.equal(b.args.token, TOKEN22);
    assert.equal(b.args.spa, true);
    assert.equal(t.puts.length, 1);
    const p = t.puts[0];
    assert.equal(p.method, "PUT");
    assert.match(p.auth, /^Bearer upl_TICKET1_/);
    assert.equal(p.ct, "application/octet-stream");
    const sent = await t.sent();
    assert.equal(sent.length, 1);
    assert.ok(sent[0].isFile && sent[0].name === "site.zip", "the body is the File itself");
    assert.ok(sent[0].bytes.equals(zipBytes) && sha(sent[0].bytes) === b.args.sha256, "bytes sent match the hash");
    // The cross-origin PUT (opaque iframe origin, Authorization header) only succeeds if the
    // mock CORS answers are honoured; Playwright answers the preflight itself, so it is not
    // visible to the route handler.
    const out = await text(f);
    assert.match(out, /site\.zip/);
    assert.match(out, new RegExp(BASE.replace(/\./g, "\\.") + "/" + TOKEN22 + "/"));
    assert.match(out, /Password protected/);
    assert.match(out, /Expires \d\d\.\d\d\.\d{4}/);
    assert.match(out, /in [67] days/);
    await f.getByRole("button", { name: "Copy" }).waitFor();
    await f.getByRole("button", { name: "Open" }).click();
    await t.panel.waitFor("ui/open-link");
    const ctx = await t.panel.waitFor("ui/update-model-context");
    assert.match(ctx[0].params.content[0].text, new RegExp("^Uploaded site\\.zip as release " + TOKEN22 + ": " + BASE + "/" + TOKEN22 + "/ \\(expires "));
    const msg = await t.panel.waitFor("ui/message");
    assert.equal(msg[0].params.content[0].text, "Uploaded site.zip: " + BASE + "/" + TOKEN22 + "/");
    assert.ok(!out.includes("upl_TICKET"), "ticket is not displayed");
    assert.ok(!out.includes(PASSWORD), "password is not displayed");
    assert.ok(!JSON.stringify(ctx).includes("upl_TICKET") && !JSON.stringify(msg).includes(PASSWORD));
    await finish(t);
  },

  "Publish as one file sends filename; archive-looking names are case-insensitive": async () => {
    const t = await setup();
    const f = t.panel.frame;
    await pick(t, makeFile("Bundle.TAR.GZ", zipBytes));
    await f.getByLabel("Publish as one file").check();
    await publishBtn(f).click();
    await f.waitForSelector("#result");
    assert.equal(t.begins[0].args.filename, "Bundle.TAR.GZ");
    assert.ok(!("password" in t.begins[0].args) && !("label" in t.begins[0].args) && !("token" in t.begins[0].args));
    assert.ok(!("spa" in t.begins[0].args) && !("expires_in_days" in t.begins[0].args), "absent options are omitted");
    await finish(t);
  },

  "a .pdf always sends filename and offers no checkbox": async () => {
    const pdf = Buffer.concat([Buffer.from("%PDF-1.4\n"), randomBytes(3000)]);
    const t = await setup({ options: { spa: true } });
    const f = t.panel.frame;
    await pick(t, makeFile("report.pdf", pdf));
    await f.getByRole("button", { name: "Publish", exact: true }).waitFor();
    assert.equal(await f.locator("#one").count(), 0, "no one-file checkbox");
    await publishBtn(f).click();
    await f.waitForSelector("#result");
    assert.equal(t.begins[0].args.filename, "report.pdf");
    assert.ok(!("spa" in t.begins[0].args), "spa is dropped for a single file");
    assert.equal(sha((await t.sent())[0].bytes), sha(pdf));
    await finish(t);
  },

  "413 with hint is shown and Try again reuses the idempotency_key": async () => {
    const t = await setup({
      put: (n) => n === 1
        ? { status: 413, json: { error: "upload too large", hint: "Reduce the file below the server limit." } }
        : { status: 201, json: releaseView() },
    });
    const f = t.panel.frame;
    await pick(t, makeFile("site.zip", zipBytes));
    await publishBtn(f).click();
    await f.getByRole("button", { name: "Try again" }).waitFor();
    const out = await text(f);
    assert.match(out, /upload too large/);
    assert.match(out, /Reduce the file below the server limit\./);
    assert.ok(!out.includes("upl_TICKET"));
    await f.getByRole("button", { name: "Try again" }).click();
    await f.waitForSelector("#result");
    assert.equal(t.begins.length, 2);
    assert.equal(t.begins[1].args.idempotency_key, t.begins[0].args.idempotency_key);
    assert.equal(t.begins[1].args.sha256, t.begins[0].args.sha256);
    assert.notEqual(t.puts[0].auth, t.puts[1].auth, "the retry uses a new ticket");
    assert.equal(t.puts.length, 2);
    // Chromium logs the 413 itself as a console error; nothing else may appear.
    const rest = t.panel.errors.filter((e) => !/status of 413/.test(e));
    assert.deepEqual(rest, []);
    await t.panel.close();
  },

  "network error shows a message and Try again works": async () => {
    const t = await setup({
      put: (n) => n === 1 ? { abort: true } : { status: 201, json: releaseView() },
    });
    const f = t.panel.frame;
    await pick(t, makeFile("site.zip", zipBytes));
    await publishBtn(f).click();
    await f.getByRole("button", { name: "Try again" }).waitFor();
    assert.match(await text(f), /Upload failed: network error/);
    await f.getByRole("button", { name: "Try again" }).click();
    await f.waitForSelector("#result");
    assert.equal(t.begins[1].args.idempotency_key, t.begins[0].args.idempotency_key);
    const rest = t.panel.errors.filter((e) => !/net::ERR_FAILED|Failed to load resource/.test(e));
    assert.deepEqual(rest, []);
    await t.panel.close();
  },

  "an upload_url outside the base is refused and no request is made": async () => {
    let requested = false;
    const t = await setup({
      begin: (args) => textResult({
        upload_url: "https://evil.example.net/_upload", method: "PUT",
        headers: { Authorization: "Bearer upl_SECRETTICKET" + "y".repeat(30) }, expires_at: new Date().toISOString(),
      }),
    });
    await t.panel.page.route("https://evil.example.net/**", (route) => { requested = true; route.abort(); });
    const f = t.panel.frame;
    await pick(t, makeFile("site.zip", zipBytes));
    await publishBtn(f).click();
    await f.getByText("Upload URL withheld").waitFor();
    await t.panel.page.waitForTimeout(200);
    assert.equal(requested, false, "nothing was sent to the foreign URL");
    assert.equal(t.puts.length, 0);
    assert.equal(await f.getByRole("button", { name: "Try again" }).count(), 0, "no retry for a withheld URL");
    assert.ok(!(await text(f)).includes("SECRETTICKET"));
    await finish(t);
  },

  "begin_upload error shows error and hint": async () => {
    const t = await setup({
      begin: () => textResult({ error: "invalid label", hint: "Use a label of at most 80 characters." }, true),
    });
    const f = t.panel.frame;
    await pick(t, makeFile("site.zip", zipBytes));
    await publishBtn(f).click();
    await f.getByRole("button", { name: "Try again" }).waitFor();
    const out = await text(f);
    assert.match(out, /invalid label/);
    assert.match(out, /Use a label of at most 80 characters\./);
    assert.equal(t.puts.length, 0);
    await finish(t);
  },

  "a file over max_bytes is refused before hashing and begin_upload": async () => {
    const t = await setup({ max: 1000 });
    const f = t.panel.frame;
    await pick(t, makeFile("big.zip", randomBytes(2048)));
    await f.getByText(/Too large: 2\.0 KB, limit 1000 B/).waitFor();
    assert.equal(t.begins.length, 0);
    assert.equal(await publishBtn(f).count(), 0, "no Publish button for a refused file");
    await finish(t);
  },

  "a tool-result error is shown with its hint and nothing can be picked": async () => {
    const panel = await openPanel("upload.html", {});
    await panel.toolInput({ password: PASSWORD });
    await panel.toolResult(textResult({ error: "invalid upload_from_computer arguments", hint: "Check the options." }, true));
    await panel.frame.getByText("Check the options.").waitFor();
    assert.equal(await panel.frame.locator("input[type=file]").count(), 0);
    assert.ok(!(await text(panel.frame)).includes(PASSWORD));
    await finish({ panel });
  },

  "ticket and password never appear in the visible text at any step": async () => {
    const t = await setup({ options: { password: PASSWORD }, put: () => ({ status: 201, json: releaseView({ protected: true }) }) });
    const f = t.panel.frame;
    const seen = [await text(f)];
    await pick(t, makeFile("site.zip", zipBytes));
    seen.push(await text(f));
    await publishBtn(f).click();
    await f.waitForSelector("#result");
    seen.push(await text(f));
    const html = await f.evaluate(() => document.documentElement.outerHTML.split("<script")[0]);
    for (const s of [...seen, html]) {
      assert.ok(!s.includes(PASSWORD), "password leaked");
      assert.ok(!s.includes("upl_"), "ticket leaked");
    }
    await finish(t);
  },

  "Cancel after sending reports uncertainty and retries identical settings": async () => {
    const t = await setup({ put: (n) => n === 1 ? { hang: true } : { status: 201, json: releaseView() } });
    const f = t.panel.frame;
    await pick(t, makeFile("site.zip", zipBytes));
    await publishBtn(f).click();
    // Wait until the endpoint receives the request, not merely the Cancel button.
    for (let i = 0; !t.puts.length && i < 100; i++) await t.panel.page.waitForTimeout(20);
    assert.equal(t.puts.length, 1, "endpoint received the upload");
    await f.getByRole("button", { name: "Cancel" }).click();
    await f.getByText("Upload stopped. Publication may have completed.").waitFor();
    assert.doesNotMatch(await text(f), /Nothing was published/);
    assert.equal(await f.locator("#one").count(), 0, "retry cannot change the file interpretation");
    await t.panel.toolInput({ label: "changed after cancellation" });
    await f.getByRole("button", { name: "Try again" }).click();
    await f.waitForSelector("#result");
    assert.deepEqual(t.begins[1].args, t.begins[0].args, "retry keeps the whole request");
    await finish(t);
  },

  "Cancel while hashing sends nothing and allows a new attempt": async () => {
    for (const phone of PHONES) {
      const t = await setup({ phone });
      const f = t.panel.frame;
      await pick(t, makeFile("site.zip", zipBytes));
      await f.evaluate(() => { window.fsSha256Hex = () => new Promise(() => {}); });
      await publishBtn(f).click();
      await f.getByRole("button", { name: "Cancel" }).click();
      await f.getByText("Upload cancelled before sending. Nothing was uploaded.").waitFor();
      assert.equal(t.begins.length, 0);
      assert.equal(t.puts.length, 0);
      await expectPhoneFit(t.panel, "cancelled before sending");
      await finish(t);
    }
  },

  "fits a phone and can be used by touch in every state": async () => {
    const long = "my-portfolio-website-export-with-a-very-long-name-2026.zip";
    for (const phone of PHONES) {
      let put = { status: 201, json: releaseView({ label: long, url: BASE + "/" + TOKEN22 + "/" + long }) };
      const t = await setup({ phone, put: () => put });
      const f = t.panel.frame;
      await expectPhoneFit(t.panel, "pick");
      // A phone has no drag and drop: the visible button opens the picker.
      const chooser = t.panel.page.waitForEvent("filechooser");
      await f.getByRole("button", { name: "Choose file" }).tap();
      await (await chooser).setFiles(makeFile(long, zipBytes));
      await publishBtn(f).waitFor();
      await expectPhoneFit(t.panel, "ready, with the archive option");
      await f.locator("label.check").tap();
      assert.equal(await f.locator("#one").isChecked(), true, "the checkbox row toggles by tap");
      await f.locator("label.check").tap();
      put = { hang: true };
      await publishBtn(f).tap();
      await f.getByRole("button", { name: "Cancel" }).waitFor();
      await expectPhoneFit(t.panel, "uploading");
      await f.getByRole("button", { name: "Cancel" }).tap();
      await f.getByRole("button", { name: "Try again" }).waitFor();
      await expectPhoneFit(t.panel, "cancelled with unknown outcome");
      put = { status: 413, json: { error: "file too large", hint: "The limit is 50 MB. Split the site or ask the owner to raise the limit." } };
      await f.getByRole("button", { name: "Try again" }).tap();
      await f.getByText("file too large").first().waitFor();
      await expectPhoneFit(t.panel, "failed");
      put = { status: 201, json: releaseView({ label: long, url: BASE + "/" + TOKEN22 + "/" + long }) };
      await f.getByRole("button", { name: "Try again" }).tap();
      await f.locator("#result").waitFor();
      await expectPhoneFit(t.panel, "done");
      // The refused PUT above is logged by the browser itself; nothing else may be.
      t.panel.errors.splice(0, t.panel.errors.length, ...t.panel.errors.filter((e) => !/status of 413/.test(e)));
      await finish(t);
    }
  },

  "drag and drop selects a file; more than one file is refused": async () => {
    const t = await setup();
    const f = t.panel.frame;
    await f.evaluate(() => {
      const dt = new DataTransfer();
      dt.items.add(new File(["a"], "a.txt"));
      dt.items.add(new File(["b"], "b.txt"));
      document.getElementById("drop").dispatchEvent(new DragEvent("drop", { dataTransfer: dt, bubbles: true, cancelable: true }));
    });
    await f.getByText("Drop one file at a time.").waitFor();
    await f.evaluate(() => {
      const zone = document.getElementById("drop");
      const dt = new DataTransfer();
      dt.items.add(new File([new Uint8Array(4096).fill(7)], "site.zip"));
      const over = new DragEvent("dragover", { dataTransfer: dt, bubbles: true, cancelable: true });
      zone.dispatchEvent(over);
      if (!over.defaultPrevented || !zone.classList.contains("over")) throw new Error("dragover not accepted");
      zone.dispatchEvent(new DragEvent("drop", { dataTransfer: dt, bubbles: true, cancelable: true }));
    });
    await f.getByLabel("Publish as one file").waitFor();
    await publishBtn(f).click();
    await f.waitForSelector("#result");
    assert.equal((await t.sent())[0].size, 4096);
    assert.equal(sha((await t.sent())[0].bytes), sha(Buffer.alloc(4096, 7)));
    await finish(t);
  },

  "Upload another file resets to the drop zone with a fresh key": async () => {
    const t = await setup();
    const f = t.panel.frame;
    await pick(t, makeFile("site.zip", zipBytes));
    await publishBtn(f).click();
    await f.waitForSelector("#result");
    await f.getByRole("button", { name: "Upload another file" }).click();
    await f.waitForSelector("#drop");
    await pick(t, makeFile("two.pdf", Buffer.from("%PDF-two")));
    await publishBtn(f).click();
    await f.waitForSelector("#result");
    assert.equal(t.begins.length, 2);
    assert.notEqual(t.begins[0].args.idempotency_key, t.begins[1].args.idempotency_key);
    assert.equal(t.begins[1].args.filename, "two.pdf");
    await finish(t);
  },

  "a result URL outside the base is withheld": async () => {
    const t = await setup({ put: () => ({ status: 201, json: releaseView({ url: "https://evil.example.net/x/" }) }) });
    const f = t.panel.frame;
    await pick(t, makeFile("site.zip", zipBytes));
    await publishBtn(f).click();
    await f.getByText(/Link withheld/).waitFor();
    assert.equal(await f.getByRole("button", { name: "Open" }).count(), 0);
    assert.equal(await f.locator("a[href]").count(), 0);
    const ctx = await t.panel.waitFor("ui/update-model-context");
    assert.ok(!JSON.stringify(ctx).includes("evil.example.net"));
    await finish(t);
  },
};

try {
  await run("ui_upload", tests);
} finally {
  rmSync(tmp, { recursive: true, force: true });
}
