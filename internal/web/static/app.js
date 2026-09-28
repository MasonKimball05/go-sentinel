const BADGES = { ok: "✓", warn: "!", fail: "✗" };
const POLL_MS = 15_000;

const el = (id) => document.getElementById(id);
const runBtn = el("run");
let latest = null;

async function load() {
  try {
    const res = await fetch("api/status");
    const data = await res.json();
    render(data);
    // A check is mid-flight (e.g. right after launch): look again soon.
    if (data.running) setTimeout(load, 1000);
  } catch {
    el("summary").textContent = "Can't reach sentinel. Is it still running?";
    el("overall").dataset.status = "fail";
  }
}

async function runNow() {
  runBtn.disabled = true;
  runBtn.textContent = "Checking…";
  try {
    const res = await fetch("api/run", { method: "POST" });
    render(await res.json());
  } finally {
    runBtn.disabled = false;
    runBtn.textContent = "Run now";
  }
}

function render(data) {
  latest = data;
  const sites = data.sites ?? [];
  const results = sites.flatMap((s) => s.results);

  if (results.length === 0) {
    el("summary").textContent = data.running ? "Running first check…" : "No results yet";
  } else {
    const count = (st) => results.filter((r) => r.status === st).length;
    const parts = [
      `${count("ok")} passing`,
      count("warn") && `${count("warn")} warning`,
      count("fail") && `${count("fail")} failing`,
    ].filter(Boolean);
    el("summary").textContent = parts.join(" · ");
  }

  const worst = ["fail", "warn", "ok"].find((st) => sites.some((s) => s.results.length && s.status === st));
  el("overall").dataset.status = worst ?? "pending";
  document.title = worst === "fail" ? "✗ Sentinel" : "Sentinel";
  renderLastRun();
  el("alerts").textContent = data.alerts?.length ? `Alerts → ${data.alerts.join(", ")}` : "Alerts off";

  const tpl = el("site-card");
  const cards = sites.map((site) => {
    const card = tpl.content.cloneNode(true);
    card.querySelector(".dot").dataset.status = site.results.length ? site.status : "pending";
    card.querySelector("h2").textContent = site.name;
    const link = card.querySelector(".url");
    link.href = site.url;
    link.textContent = site.url.replace(/^https?:\/\//, "");

    const list = card.querySelector(".checks");
    if (site.results.length === 0) {
      list.innerHTML = `<li class="empty">Waiting for first check…</li>`;
    }
    for (const r of site.results) list.append(checkRow(r));
    return card;
  });
  el("sites").replaceChildren(...cards);
}

// Builds one row with textContent only. Details come from remote servers
// (e.g. a Server header) so they must never be parsed as HTML.
function checkRow(r) {
  const li = document.createElement("li");
  li.className = "check";

  const badge = document.createElement("span");
  badge.className = "badge";
  badge.dataset.status = r.status;
  badge.textContent = BADGES[r.status];
  badge.title = r.status;

  const name = document.createElement("span");
  name.className = "name";
  name.textContent = r.check;

  // Multi-problem details are "; "-separated: show one per line.
  const detail = document.createElement("ul");
  detail.className = "detail";
  for (const part of r.detail.split("; ")) {
    const item = document.createElement("li");
    item.textContent = part;
    detail.append(item);
  }

  li.append(badge, name, detail);
  return li;
}

function renderLastRun() {
  if (!latest) return;
  const last = new Date(latest.last_run);
  if (latest.running || last.getFullYear() < 2000) {
    el("last-run").textContent = latest.running ? "Checking now…" : "";
    return;
  }
  const ago = Math.round((Date.now() - last) / 1000);
  const next = Math.max(0, latest.interval_seconds - ago);
  el("last-run").textContent = `Checked ${fmt(ago)} ago · next in ${fmt(next)}`;
}

function fmt(sec) {
  if (sec < 60) return `${sec}s`;
  const m = Math.floor(sec / 60);
  return m < 60 ? `${m}m` : `${Math.floor(m / 60)}h ${m % 60}m`;
}

runBtn.addEventListener("click", runNow);
load();
setInterval(load, POLL_MS);
setInterval(renderLastRun, 1000);
