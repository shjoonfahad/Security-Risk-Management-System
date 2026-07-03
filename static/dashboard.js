(function(){
  const btn = document.getElementById('notifyBtn');
  const dot = document.getElementById('notifyDot');
  const panel = document.getElementById('notifyPanel');
  const list = document.getElementById('notifyList');

  if(!btn || !panel || !list || !dot) return;

  let open = false;
  btn.addEventListener('click', ()=>{
    open = !open;
    panel.classList.toggle('hidden', !open);
  });

  async function fetchAlerts(){
    try{
      const r = await fetch('/api/alerts');
      if(!r.ok) return;
      const d = await r.json();
      // dot:
      if(d.count > 0){ dot.classList.remove('hidden'); } else { dot.classList.add('hidden'); }
      // list:
      list.innerHTML = '';
      if(d.items.length === 0){
        list.innerHTML = `<div class="notify-item"><span class="small">No new high-risk alerts (last 7 days).</span></div>`;
      } else {
        d.items.forEach(it=>{
          const row = document.createElement('div');
          row.className = 'notify-item';
          row.innerHTML = `<b>${it.asset_name}</b> — <span class="small">${it.department || 'N/A'} • Score ${it.risk_score}</span>`;
          list.appendChild(row);
        });
      }
    }catch(e){ /* silent */ }
  }

  fetchAlerts();
  setInterval(fetchAlerts, 15000);
})();

