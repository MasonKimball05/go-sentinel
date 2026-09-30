const BADGES = { ok: "✓", warn: "!", fail: "✗" };
const NAMES = {
  status: "Reachability",
  tls: "HTTPS certificate",
  "pq-tls": "Post-quantum TLS",
  headers: "Security headers",
  "info-leak": "Version disclosure",
};

const $ = (id) => document.getElementById(id);
const form = $("form"), input = $("url"), button = $("go");

// Let the page be shared with a site pre-filled: /?url=example.com
const initial = new URLSearchParams(location.search).get("url");
if (initial) {
  input.value = initial;
  run(initial);
}

form.addEventListener("submit", (e) => {
  e.preventDefault();
  run(input.value);
});

async function run(target) {
  $("error").hidden = true;
  button.disabled = true;
  button.textContent = "Checking…";
  try {
    const res = await fetch(`api/check?url=${encodeURIComponent(target)}`);
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || `Request failed (${res.status})`);
    render(data);
    history.replaceState(null, "", `?url=${encodeURIComponent(target)}`);
  } catch (err) {
    $("report").hidden = true;
    $("error").textContent = err.message;
    $("error").hidden = false;
  } finally {
    button.disabled = false;
    button.textContent = "Check";
  }
}

// Everything from the server is inserted with textContent: result details
// quote headers from arbitrary websites and must never be parsed as HTML.
function render(data) {
  const grade = $("grade");
  grade.textContent = data.grade;
  grade.dataset.grade = data.grade;
  $("site").textContent = data.url;
  $("score").textContent =
    data.grade === "?"
      ? "Couldn't reach the site, so there's nothing to grade."
      : `${data.score}/100 · checked ${new Date(data.checked_at).toLocaleTimeString()}${data.cached ? " (cached)" : ""}`;

  const tpl = $("finding");
  const items = data.results.map((r) => {
    const li = tpl.content.cloneNode(true);
    const badge = li.querySelector(".badge");
    badge.textContent = BADGES[r.status] ?? "·";
    badge.dataset.status = r.status;
    li.querySelector(".name").textContent = NAMES[r.check] ?? r.check;
    li.querySelector(".detail").textContent = r.detail;
    li.querySelector(".tip").textContent = r.tip ?? "";
    return li;
  });
  $("findings").replaceChildren(...items);
  $("report").hidden = false;
}
