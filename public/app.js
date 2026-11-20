const state = {
  principal: null,
  principals: [],
  subjects: [],
  subject: null,
  snapshot: null,
  pack: null,
  footprint: null,
  busy: false,
};

const $ = (sel) => document.querySelector(sel);
const el = (tag, props = {}, ...children) => {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(props)) {
    if (key === 'class') node.className = value;
    else if (key === 'text') node.textContent = value;
    else if (key === 'html') node.innerHTML = value;
    else if (key.startsWith('on')) node.addEventListener(key.slice(2), value);
    else if (value !== null && value !== undefined) node.setAttribute(key, value);
  }
  for (const child of children.flat()) {
    if (child === null || child === undefined) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
};

const fmtBytes = (n) => (n >= 1024 ? `${(n / 1024).toFixed(1)} kB` : `${n} B`);
const fmtTime = (iso) => (iso ? new Date(iso).toLocaleString([], { dateStyle: 'medium', timeStyle: 'short' }) : '—');
const short = (hash, n = 16) => (hash ? `${hash.slice(0, n)}…` : '—');

let toastTimer;
function toast(message, isError = false) {
  const node = $('#toast');
  node.textContent = message;
  node.hidden = false;
  node.style.background = isError ? 'var(--critical)' : 'var(--text-primary)';
  node.style.color = isError ? '#fff' : 'var(--surface-1)';
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { node.hidden = true; }, 4200);
}

async function api(path, { method = 'GET', body } = {}) {
  const headers = {};
  if (state.principal) headers['X-Api-Key'] = state.principal.api_key;
  if (body) headers['Content-Type'] = 'application/json';
  const res = await fetch(path, { method, headers, body: body ? JSON.stringify(body) : undefined });
  const type = res.headers.get('content-type') || '';
  const data = type.includes('application/json') ? await res.json() : await res.text();
  if (!res.ok) {
    const message = data?.error || `request failed (${res.status})`;
    const error = new Error(message);
    error.status = res.status;
    error.data = data;
    throw error;
  }
  return data;
}

function setBusy(busy) {
  state.busy = busy;
  for (const id of ['#build', '#step', '#interrupt', '#resume', '#download', '#verify', '#subject', '#snapshot', '#as-of', '#redacted']) {
    const node = $(id);
    if (node) node.disabled = busy || node.dataset.lock === '1';
  }
}

function applyStageLocks() {
  const pack = state.pack?.pack;
  const status = pack?.status;
  const terminal = status === 'complete' || status === 'incomplete';
  // Stepping is only meaningful while a pack is unfinished and not interrupted;
  // an interrupted pack resumes through the explicit Resume action.
  $('#step').dataset.lock = terminal || status === 'interrupted' || status === 'failed' ? '1' : '0';
  $('#interrupt').dataset.lock = status === 'building' ? '0' : '1';
  $('#resume').dataset.lock = status === 'interrupted' || status === 'failed' ? '0' : '1';
  $('#download').dataset.lock = terminal && pack?.root_hash ? '0' : '1';
  $('#verify').dataset.lock = pack?.root_hash ? '0' : '1';
  for (const id of ['#step', '#interrupt', '#resume', '#download', '#verify']) {
    const node = $(id);
    if (node) node.disabled = state.busy || node.dataset.lock === '1';
  }
}

/* ---------- principals & scope ---------- */

async function loadPrincipals() {
  const principals = await api('/api/principals');
  state.principals = principals;
  const select = $('#principal');
  select.replaceChildren();
  for (const p of principals) {
    select.append(el('option', { value: p.id, text: `${p.name} — ${p.role} · ${p.workspace}${p.clearance === 'restricted' ? ' · restricted clearance' : ''}` }));
  }
  const preferred = localStorage.getItem('evidence.principal');
  select.value = principals.some((p) => p.id === preferred) ? preferred : principals[0].id;
  await selectPrincipal(select.value);
}

async function selectPrincipal(id) {
  const principals = await api('/api/principals');
  const principal = principals.find((p) => p.id === id);
  if (!principal) return;
  state.principals = principals;
  state.principal = { ...principal, api_key: await revealKey(id) };
  $('#keychip').textContent = `…${principal.hint}`;
  localStorage.setItem('evidence.principal', id);
  await loadSubjects();
}

// The discovery endpoint only exposes a suffix; the full demo key is derived
// from the seeded fixture so the console can authenticate without a login flow.
async function revealKey(id) {
  const demoKeys = {
    p_auditor: 'key-auditor-demo',
    p_steward: 'key-steward-demo',
    p_viewer: 'key-viewer-demo',
    p_platform: 'key-platform-demo',
    p_outsider: 'key-outsider-demo',
  };
  return demoKeys[id] ?? id;
}

async function loadSubjects() {
  const subjects = await api('/api/subjects');
  state.subjects = subjects;
  const select = $('#subject');
  select.replaceChildren();
  for (const s of subjects) {
    select.append(el('option', {
      value: s.id,
      text: `${s.title} · ${s.kind}${s.classification === 'restricted' ? ' · restricted' : ''}${s.workspace !== state.principal.workspace ? ` · ${s.workspace}` : ''}`,
    }));
  }
  const keep = state.subject?.id;
  select.value = subjects.some((s) => s.id === keep) ? keep : subjects[0]?.id;
  await selectSubject(select.value);
}

function resetRun() {
  state.pack = null;
  $('#run-panel').hidden = true;
  $('#kpi-panel').hidden = true;
  $('#gaps-panel').hidden = true;
  $('#hash-panel').hidden = true;
  $('#downloads-panel').hidden = true;
  $('#verify-out').hidden = true;
  applyStageLocks();
}

async function selectSubject(id) {
  state.subject = state.subjects.find((s) => s.id === id) ?? null;
  if (!state.subject) return;
  resetRun();
  const footprint = await api(`/api/subjects/${encodeURIComponent(id)}/footprint`);
  state.footprint = footprint;
  const select = $('#snapshot');
  select.replaceChildren();
  const refs = footprint.snapshots.map((s) => s.ref);
  // Include the missing-snapshot probe so the gap behaviour is demonstrable.
  if (refs.length === 0) {
    select.append(el('option', { value: 'snap.none', text: '— no snapshots recorded —' }));
  } else {
    for (const s of footprint.snapshots) {
      select.append(el('option', { value: s.ref, text: `${s.ref} · captured ${fmtTime(s.captured_at)}` }));
    }
    select.append(el('option', { value: 'snap.unknown', text: 'snap.unknown (probe a missing snapshot)' }));
  }
  state.snapshot = select.value;
  renderFootprint();
}

function renderFootprint() {
  const node = $('#footprint');
  node.replaceChildren();
  const f = state.footprint;
  if (!f) return;
  if (f.subject.workspace !== state.principal.workspace) {
    node.append(el('span', { class: 'fp' }, el('span', { class: 'dot off' }),
      `Subject is in ${f.subject.workspace}; you act in ${state.principal.workspace} — collection and download will be denied.`));
    return;
  }
  const items = [
    ['Snapshots', f.snapshots.length],
    ['Transform versions', f.counts.transforms],
    ['Quality runs', f.counts.quality],
    ['Permission records', f.counts.permissions],
    ['Publish events', f.counts.publish],
  ];
  for (const [label, count] of items) {
    node.append(el('span', { class: 'fp' }, el('span', { class: `dot${count > 0 ? '' : ' off'}` }), `${label}: ${count}`));
  }
  if (f.subject.classification === 'restricted') {
    const cleared = state.principal.role === 'auditor' || state.principal.clearance === 'restricted';
    node.append(el('span', { class: 'fp' },
      el('span', { class: `dot${cleared ? '' : ' off'}` }),
      cleared
        ? 'Restricted: identifiers are pseudonymised in the pack.'
        : `Restricted: your role (${state.principal.role}) has no clearance — build and download will be denied.`));
  }
}

/* ---------- run flow ---------- */

async function refreshPack(id = state.pack?.pack?.id) {
  if (!id) return;
  const detail = await api(`/api/packs/${encodeURIComponent(id)}`);
  state.pack = detail;
  renderPack();
}

async function startPack(stepMode) {
  const subjectId = $('#subject').value;
  const snapshotRef = $('#snapshot').value;
  if (!subjectId || !snapshotRef) return;
  // Empty means "use the snapshot's capture time", which keeps repeat builds
  // byte-identical instead of drifting with the clock.
  const asOf = $('#as-of').value ? new Date($('#as-of').value).toISOString() : undefined;
  const redacted = $('#redacted').checked;
  try {
    const created = await api('/api/packs', {
      method: 'POST',
      body: { subject_id: subjectId, snapshot_ref: snapshotRef, as_of: asOf, redacted },
    });
    state.pack = null;
    await refreshPack(created.pack.id);
    if (created.resumed && created.pack.status === 'interrupted') {
      toast('This scope has an interrupted build. Press Resume to finish it — collected stages are already persisted.');
    } else if (created.resumed) {
      toast('Reused the existing pack for this scope — unchanged sources reproduce the same checksum.');
    }
    $('#run-panel').hidden = false;
    $('#run-panel').scrollIntoView({ behavior: 'smooth', block: 'start' });
    if (stepMode) {
      // A single click should collect one dimension, not merely create the pack.
      if (created.pack.status === 'building') await advanceOne();
    } else {
      await runToCompletion();
    }
  } catch (error) {
    toast(error.message, true);
    await loadRecent();
  }
}

async function runToCompletion() {
  setBusy(true);
  try {
    let guard = 0;
    while (state.pack?.pack?.status === 'building' && guard < 20) {
      guard += 1;
      await api(`/api/packs/${encodeURIComponent(state.pack.pack.id)}/advance`, { method: 'POST' });
      await refreshPack();
      await sleep(380);
    }
    await refreshPack();
    if (state.pack.pack.status === 'complete' || state.pack.pack.status === 'incomplete') {
      toast(state.pack.pack.status === 'complete'
        ? 'Pack complete — every required source resolved.'
        : 'Pack finished with gaps: it is marked incomplete, not clean.');
    }
  } catch (error) {
    toast(error.message, true);
    if (state.pack) await refreshPack();
  } finally {
    setBusy(false);
    applyStageLocks();
    await loadRecent();
  }
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function advanceOne() {
  if (!state.pack?.pack?.id) return;
  setBusy(true);
  try {
    await api(`/api/packs/${encodeURIComponent(state.pack.pack.id)}/advance`, { method: 'POST' });
    await refreshPack();
    applyStageLocks();
  } catch (error) {
    toast(error.message, true);
  } finally {
    setBusy(false);
  }
}

async function interrupt() {
  if (!state.pack?.pack?.id) return;
  try {
    await api(`/api/packs/${encodeURIComponent(state.pack.pack.id)}/interrupt`, { method: 'POST' });
    await refreshPack();
    applyStageLocks();
    toast('Collection interrupted. Collected stages are persisted; resume continues from the first pending stage.');
  } catch (error) {
    toast(error.message, true);
  }
}

async function resume() {
  if (!state.pack?.pack?.id) return;
  setBusy(true);
  try {
    await api(`/api/packs/${encodeURIComponent(state.pack.pack.id)}/resume`, { method: 'POST' });
    await refreshPack();
    toast('Resumed and finished collection from the persisted checkpoint.');
  } catch (error) {
    toast(error.message, true);
    await refreshPack();
  } finally {
    setBusy(false);
    applyStageLocks();
    await loadRecent();
  }
}

async function download() {
  if (!state.pack?.pack?.id) return;
  try {
    const res = await fetch(`/api/packs/${encodeURIComponent(state.pack.pack.id)}/download`, {
      headers: { 'X-Api-Key': state.principal.api_key },
    });
    if (!res.ok) {
      const data = await res.json().catch(() => ({}));
      throw new Error(data.error || `download failed (${res.status})`);
    }
    const blob = await res.blob();
    const disposition = res.headers.get('content-disposition') || '';
    const name = /filename="([^"]+)"/.exec(disposition)?.[1] || 'evidence.zip';
    const url = URL.createObjectURL(blob);
    const link = el('a', { href: url, download: name });
    document.body.append(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 5000);
    toast(`Downloaded ${name} · root ${short(res.headers.get('X-Evidence-Root'), 12)}`);
    await refreshPack();
  } catch (error) {
    toast(error.message, true);
    await refreshPack();
  }
}

async function verify() {
  if (!state.pack?.pack?.id) return;
  const out = $('#verify-out');
  try {
    const result = await api(`/api/packs/${encodeURIComponent(state.pack.pack.id)}/verify`);
    out.hidden = false;
    out.className = `verify-out ${result.ok ? 'ok' : 'bad'}`;
    out.replaceChildren(
      el('strong', { text: result.ok ? 'Verified — recomputed root matches the sealed manifest.' : 'Verification failed.' }),
      el('div', { class: 'mono', style: 'margin-top:6px;word-break:break-all', text: `stored     ${result.stored_root ?? '—'}` }),
      el('div', { class: 'mono', style: 'word-break:break-all', text: `recomputed ${result.recomputed_root ?? '—'}` }),
    );
    for (const problem of result.problems ?? []) {
      out.append(el('div', { style: 'color:var(--critical);margin-top:4px', text: problem }));
    }
  } catch (error) {
    toast(error.message, true);
  }
}

/* ---------- rendering ---------- */

function renderPack() {
  const pack = state.pack;
  if (!pack) return;
  $('#run-panel').hidden = false;
  $('#kpi-panel').hidden = false;
  $('#gaps-panel').hidden = false;
  $('#hash-panel').hidden = false;
  $('#downloads-panel').hidden = false;

  const status = pack.pack.status;
  const terminal = status === 'complete' || status === 'incomplete';
  const progress = pack.progress;
  const hasGap = pack.stages.some((s) => s.status === 'gap' || s.status === 'failed');

  const meter = $('#meter');
  meter.classList.toggle('is-gap', hasGap);
  meter.classList.toggle('is-complete', status === 'complete');
  meter.setAttribute('aria-valuenow', String(progress.percent));
  $('#meter-fill').style.width = `${progress.percent}%`;
  $('#progress-text').textContent = `${progress.done} of ${progress.total} sources collected`
    + (progress.current && !terminal ? ` · next: ${progress.current}` : '');

  $('#run-meta').replaceChildren(
    el('div', {}, el('span', { class: `badge ${status}`, text: status })),
    el('div', { style: 'margin-top:6px' }, pack.pack.snapshot_ref, ' · ', pack.pack.id),
    el('div', { text: `as of ${fmtTime(pack.pack.as_of)} · ${pack.manifest?.as_of_basis?.replaceAll('_', ' ') ?? 'pending'}` }),
    pack.pack.redacted ? el('div', { text: 'identifiers redacted' }) : null,
  );

  const list = $('#stages');
  list.replaceChildren();
  const titles = {
    inputs: 'Input snapshot',
    transforms: 'Transform versions',
    quality: 'Quality results',
    permissions: 'Permission records',
    publish: 'Publish logs',
  };
  for (const stage of pack.stages) {
    const icon = { collected: '✓', gap: '!', failed: '✕', running: '…', pending: '' }[stage.status] ?? '';
    const tag = {
      collected: 'collected', gap: 'gap — blocked', failed: 'failed', running: 'collecting', pending: 'pending',
    }[stage.status] ?? stage.status;
    list.append(el('li', { class: `stage is-${stage.status}` },
      el('span', { class: 'stage-icon', 'aria-hidden': 'true', text: icon }),
      el('div', {},
        el('div', { class: 'stage-name', text: titles[stage.key] ?? stage.key }),
        el('div', { class: 'stage-detail', text: stage.detail ?? 'not yet collected' }),
      ),
      el('span', { class: 'stage-tag', text: tag }),
    ));
  }

  const blocking = pack.gaps.filter((g) => g.severity === 'blocking');
  const advisory = pack.gaps.filter((g) => g.severity === 'advisory');
  const collected = pack.stages.filter((s) => s.status === 'collected').length;

  const kpis = $('#kpis');
  kpis.replaceChildren(
    kpi('Pack status', status, {
      dot: status,
      foot: terminal ? (blocking.length ? 'not safe to present as complete' : 'all required sources resolved') : 'collection in progress',
      status: true,
    }),
    kpi('Sources collected', `${collected}/${progress.total}`, { foot: `${progress.percent}% of required evidence` }),
    kpi('Blocking gaps', String(blocking.length), { foot: blocking.length ? 'pack is incomplete' : 'none' }),
    kpi('Advisory gaps', String(advisory.length), { foot: 'disclosed, non-blocking' }),
    kpi('Artifacts', String(pack.artifacts.length), { foot: `${fmtBytes(pack.artifacts.reduce((a, x) => a + x.bytes, 0))} total` }),
    kpi('Root hash', pack.pack.root_hash ? short(pack.pack.root_hash, 14) : '—', { small: true, foot: 'SHA-256, canonical manifest' }),
  );

  renderGaps(pack.gaps);
  renderArtifacts(pack);
  renderDownloads(pack.downloads);
  applyStageLocks();
}

function kpi(label, value, { foot, dot, status, small } = {}) {
  const valueNode = el('div', { class: `value${small ? ' small' : ''}` });
  if (dot) {
    valueNode.append(el('span', { class: `status-dot ${dot}`, 'aria-hidden': 'true' }));
    valueNode.append(document.createTextNode(String(value)));
  } else {
    valueNode.textContent = value;
  }
  return el('div', { class: 'kpi' },
    el('div', { class: 'label', text: label }),
    valueNode,
    foot ? el('div', { class: 'foot', text: foot }) : null,
  );
}

function renderGaps(gaps) {
  const node = $('#gaps');
  node.replaceChildren();
  if (!gaps.length) {
    node.append(el('div', { class: 'empty', text: 'No gaps recorded. Every required source resolved for this scope.' }));
    return;
  }
  const order = { blocking: 0, advisory: 1 };
  for (const gap of [...gaps].sort((a, b) => order[a.severity] - order[b.severity])) {
    node.append(el('div', { class: `gap ${gap.severity}` },
      el('span', { class: 'gap-icon', 'aria-hidden': 'true', text: gap.severity === 'blocking' ? '⛔' : '⚠' }),
      el('div', {},
        el('div', { class: 'gap-title' }, gap.kind.replaceAll('_', ' '), ' ', el('span', { class: `badge ${gap.severity}`, text: gap.severity })),
        el('div', { class: 'gap-detail', text: gap.detail }),
        el('div', { class: 'gap-meta' },
          el('span', { text: `dimension: ${gap.dimension}` }),
          gap.ref ? el('span', { class: 'mono', text: gap.ref }) : null,
          gap.redacted ? el('span', { text: 'identifiers redacted' }) : null,
        ),
      ),
    ));
  }
}

function renderArtifacts(pack) {
  const rootNode = $('#root-hash');
  rootNode.replaceChildren();
  if (pack.manifest?.checksum) {
    rootNode.append(
      el('span', { class: 'rh-label', text: 'Root hash' }),
      el('code', { text: `sha256:${pack.manifest.checksum.root}` }),
      el('span', { class: `badge ${pack.manifest.status}`, text: pack.manifest.status }),
    );
  } else {
    rootNode.append(el('span', { class: 'rh-label', text: 'Root hash is written when collection finishes.' }));
  }
  const body = $('#artifacts');
  body.replaceChildren();
  if (!pack.artifacts.length) {
    body.append(el('tr', {}, el('td', { colspan: '4' }, el('div', { class: 'empty', text: 'No artifacts yet.' }))));
    return;
  }
  for (const artifact of pack.artifacts) {
    body.append(el('tr', {},
      el('td', {},
        el('div', { class: 'mono', text: artifact.path }),
        el('div', { style: 'color:var(--muted);font-size:11.5px', text: artifact.dimension + (artifact.redaction ? ' · redacted' : '') }),
      ),
      el('td', { class: 'num', text: artifact.record_count ?? '—' }),
      el('td', { class: 'num', text: artifact.bytes }),
      el('td', {}, el('code', { text: artifact.sha256 })),
    ));
  }
}

function renderDownloads(downloads) {
  const body = $('#downloads');
  body.replaceChildren();
  if (!downloads.length) {
    body.append(el('tr', {}, el('td', { colspan: '7' }, el('div', { class: 'empty', text: 'No download attempts for this pack yet.' }))));
    return;
  }
  for (const row of downloads) {
    body.append(el('tr', {},
      el('td', { text: fmtTime(row.at) }),
      el('td', { text: row.principal_name ?? row.principal_id }),
      el('td', { text: row.principal_role ?? '—' }),
      el('td', { text: row.action }),
      el('td', {}, el('span', { class: `result ${row.status}` }, el('i'), row.status)),
      el('td', { class: 'num', text: row.status === 'allowed' ? fmtBytes(row.bytes) : '—' }),
      el('td', { text: row.note ?? '—' }),
    ));
  }
}

async function loadRecent() {
  try {
    const packs = await api('/api/packs');
    const body = $('#recent');
    body.replaceChildren();
    if (!packs.length) {
      body.append(el('tr', {}, el('td', { colspan: '7' }, el('div', { class: 'empty', text: 'No packs built yet.' }))));
      return;
    }
    for (const pack of packs.slice(0, 12)) {
      body.append(el('tr', {},
        el('td', { text: pack.subject_id }),
        el('td', { class: 'mono', text: pack.snapshot_ref }),
        el('td', {}, el('span', { class: `badge ${pack.status}`, text: pack.status })),
        el('td', { class: 'num', text: pack.gaps.blocking ? `${pack.gaps.blocking} blocking` : `${pack.gaps.total}` }),
        el('td', {}, el('code', { text: pack.root_hash ? short(pack.root_hash, 14) : '—' })),
        el('td', { text: fmtTime(pack.created_at) }),
        el('td', {}, el('button', { class: 'ghost', type: 'button', onclick: async () => {
          state.pack = null;
          await refreshPack(pack.id);
          $('#run-panel').scrollIntoView({ behavior: 'smooth' });
        } }, 'Open')),
      ));
    }
  } catch (error) {
    toast(error.message, true);
  }
}

/* ---------- wiring ---------- */

function initDefaults() {
  const asOf = $('#as-of');
  asOf.value = '';
  asOf.placeholder = 'snapshot capture time';
  asOf.title = 'Leave empty to seal the pack as of the snapshot\'s capture time (repeatable checksum).';
}

async function boot() {
  initDefaults();
  try {
    await loadPrincipals();
    await loadRecent();
  } catch (error) {
    toast(error.message, true);
  }

  $('#principal').addEventListener('change', async (event) => {
    await selectPrincipal(event.target.value);
  });
  $('#subject').addEventListener('change', async (event) => {
    await selectSubject(event.target.value);
  });
  $('#snapshot').addEventListener('change', (event) => {
    state.snapshot = event.target.value;
    if (state.pack && state.pack.pack.snapshot_ref !== event.target.value) resetRun();
  });
  $('#scope-form').addEventListener('submit', async (event) => {
    event.preventDefault();
    await startPack(false);
  });
  $('#step').addEventListener('click', async () => {
    if (!state.pack?.pack?.id || state.pack.pack.status !== 'building' && state.pack.pack.status !== 'complete' && state.pack.pack.status !== 'incomplete') {
    await startPack(true);
  } else if (state.pack.pack.status === 'building') {
    await advanceOne();
  } else {
    await startPack(true);
  }
  });
  $('#interrupt').addEventListener('click', interrupt);
  $('#resume').addEventListener('click', resume);
  $('#download').addEventListener('click', download);
  $('#verify').addEventListener('click', verify);
  $('#refresh-recent').addEventListener('click', loadRecent);
  applyStageLocks();
}

boot();
