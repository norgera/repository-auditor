// Runs the compiled extension logic against real registry processes. Run from extension/: npm test
const { test, before, after } = require("node:test");
const assert = require("node:assert");
const { spawn } = require("node:child_process");
const path = require("node:path");
const { RegistryClient } = require("../out/registryClient.js");
const { evaluate, BUILT_IN } = require("../out/profiles.js");
const { runScan } = require("../out/scanClient.js");

const ROOT = path.resolve(__dirname, "..", "..");
const TOKEN = "test-token";
const A = "http://127.0.0.1:18701", B = "http://127.0.0.1:18702";
const META = { id: "s9", name: "Nine", description: "test", capabilities: ["cap"], url: "http://127.0.0.1:1", version: "1", tool: null, accepts: ["*"], inputMode: "files", maxBytes: 10 };
let procA, procB;

function start(name, port) {
  return spawn("python3", ["-m", "registry_service.app"], { cwd: ROOT, stdio: "ignore", env: { ...process.env, PYTHONPATH: ROOT, PYTHONDONTWRITEBYTECODE: "1", REGISTRY_NAME: name, PORT: String(port), REGISTRY_TOKEN: TOKEN, LEASE_TTL: "60" } });
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
async function up(url) {
  for (let i = 0; i < 100; i++) {
    try { if ((await fetch(url + "/health")).ok) return; } catch {}
    await sleep(50);
  }
  throw new Error("registry did not start: " + url);
}
async function seed(url) {
  const r = await fetch(url + "/v1/services", { method: "POST", headers: { "X-Registration-Token": TOKEN }, body: JSON.stringify(META) });
  assert.strictEqual(r.status, 201);
}

before(async () => {
  procA = start("A", 18701); procB = start("B", 18702);
  await up(A); await up(B); await seed(A); await seed(B);
});
after(() => { procA.kill("SIGKILL"); procB.kill("SIGKILL"); });

test("hung primary falls back within 5 s, then returns after a probe, and a dead pair goes stale", async () => {
  const client = new RegistryClient({ urls: [A, B], probeIntervalMs: 200 });
  assert.strictEqual((await client.search("cap")).source, "primary");
  await client.search("");

  procA.kill("SIGSTOP");
  const t0 = Date.now();
  const fallback = await client.search("cap");
  const elapsed = Date.now() - t0;
  assert.strictEqual(fallback.source, "backup");
  assert.deepStrictEqual(fallback.services.map((s) => s.id), ["s9"]);
  assert.ok(elapsed <= 5000, `fallback took ${elapsed} ms`);
  console.log(`fallback from hung primary: ${elapsed} ms`);

  assert.strictEqual((await client.search("cap")).source, "backup", "stays on the backup without another 3 s wait");
  procA.kill("SIGCONT");
  await sleep(300);
  await client.search("cap"); // triggers the probe
  await sleep(200);
  assert.strictEqual((await client.search("cap")).source, "primary");

  procA.kill("SIGKILL"); procB.kill("SIGKILL");
  await sleep(200);
  const stale = await client.search("cap");
  assert.strictEqual(stale.source, "stale");
  assert.deepStrictEqual(stale.services.map((s) => s.id), ["s9"]);
});

test("only a complete scan can be ready", () => {
  const base = { service: "s", tool: null, toolVersion: null, message: "m", skipped: [], findings: [] };
  const profile = BUILT_IN.production;
  assert.strictEqual(evaluate({ ...base, status: "complete" }, profile).verdict, "ready");
  for (const status of ["partial", "unsupported", "too_large", "timeout", "error"]) {
    assert.strictEqual(evaluate({ ...base, status }, profile).verdict, "incomplete", status);
  }
  const finding = { rule: "r", severity: "medium", file: "f", location: "l", message: "m" };
  assert.strictEqual(evaluate({ ...base, status: "complete", findings: [finding] }, profile).verdict, "blocked");
  assert.strictEqual(evaluate({ ...base, status: "complete", findings: [finding] }, BUILT_IN.development).verdict, "ready");
});

test("unreachable scanner and contract violations are errors", async () => {
  const down = await runScan({ id: "x", url: "http://127.0.0.1:1" }, [], {});
  assert.strictEqual(down.status, "error");
  const http = require("node:http");
  const server = http.createServer((_, res) => res.end(JSON.stringify({ status: "complete" }))).listen(0);
  await new Promise((r) => server.once("listening", r));
  const bad = await runScan({ id: "x", url: `http://127.0.0.1:${server.address().port}` }, [], {});
  server.close();
  assert.strictEqual(bad.status, "error");
});
