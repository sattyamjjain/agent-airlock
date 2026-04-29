// airlock graph — vanilla JS poller. Refreshes the snapshot every 5s.
(function () {
  const tbody = document.querySelector("#edges tbody");
  const status = document.querySelector("#status");

  function render(snap) {
    tbody.innerHTML = "";
    for (const e of snap.edges) {
      const tr = document.createElement("tr");
      tr.classList.add(`edge-${e.verdict}`);
      const cells = [e.src, e.dst, e.verdict, e.count, e.last_envelope_id || ""];
      for (const c of cells) {
        const td = document.createElement("td");
        td.textContent = c;
        tr.appendChild(td);
      }
      tbody.appendChild(tr);
    }
    status.textContent = `${snap.nodes.length} nodes, ${snap.edges.length} edges (refreshed ${snap.generated_at})`;
  }

  async function tick() {
    try {
      const r = await fetch("/api/snapshot", { cache: "no-store" });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      const snap = await r.json();
      render(snap);
    } catch (err) {
      status.textContent = `Snapshot fetch failed: ${err}`;
    }
  }
  tick();
  setInterval(tick, 5000);
})();
