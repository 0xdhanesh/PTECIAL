'use strict';
const $ = (s, root = document) => root.querySelector(s);
const make = (tag, value) => Object.assign(document.createElement(tag), {textContent:value ?? ''});
const byId = new Map(library.flatMap(area => area.cases.map(c => [c.id, c])));
const records = new Map();
const notebook = {id:'shared-fields'};
const attachments = new Map();
const prefix = 'ptecial.notebook.v2.';
const objectURLs = new Set();
const empty = () => ({outcome:'Open', severity:'Not assessed', impact:'', reason:'', retest:'', entries:[]});
let active = library[0], db, storageProblem = '', busy = 0;
const customCases = new Map();
const message = (s, error = false) => {
  $('#saved').textContent = s;
  $('#saved').classList.toggle('error', error);
};
function read(key) {
  try { return localStorage.getItem(key); }
  catch { storageProblem = 'Browser storage unavailable'; return null; }
}
function write(key, value) {
  try { localStorage.setItem(key, value); return true; }
  catch { message('Could not save in this browser. Export your notes.', true); return false; }
}
function record(id) {
  if (!records.has(id)) records.set(id, empty());
  const r = records.get(id);
  if (!r.severity) r.severity = 'Not assessed';
  if (r.impact === undefined) r.impact = '';
  if (r.reason === undefined) r.reason = '';
  if (r.retest === undefined) r.retest = '';
  return r;
}
function save(id) {
  if (write(prefix + id, JSON.stringify(record(id)))) message(storageProblem || 'Saved on this device', Boolean(storageProblem));
  metrics();
  updateFindingsSummary();
}
function metrics() {
  const ids = active.cases.map(c => c.id);
  const reviewed = ids.filter(id => record(id).outcome !== 'Open').length;
  const evidence = ids.filter(id => record(id).entries.length || attachments.get(id)?.length).length;
  $('#case-count').textContent = ids.length;
  $('#review-count').textContent = reviewed;
  $('#evidence-count').textContent = evidence;
  $('#percent').textContent = Math.round(100 * reviewed / ids.length) + '%';
  $('#progress').value = 100 * reviewed / ids.length;
}
function updateFindingsSummary() {
  const el = $('#findings-summary');
  if (!el) return;
  const findings = [];
  const counts = {Critical:0, High:0, Medium:0, Low:0, Informational:0, 'Not assessed':0};
  for (const area of library) {
    for (const c of area.cases) {
      const r = record(c.id);
      if (r.outcome === 'Finding') {
        findings.push({id:c.id, title:c.title, severity:r.severity, area:area.name});
        counts[r.severity] = (counts[r.severity] || 0) + 1;
      }
    }
  }
  el.innerHTML = '';
  const title = make('h3', 'Findings summary');
  el.append(title);
  const summary = make('p');
  summary.textContent = Object.entries(counts).filter(([,n]) => n).map(([k,n]) => k + ': ' + n).join(' · ') || 'No findings yet.';
  el.append(summary);
  if (findings.length) {
    const list = make('ul');
    findings.slice(0, 20).forEach(f => {
      const li = make('li', f.id + ' · ' + f.title + ' (' + f.severity + ')');
      list.append(li);
    });
    if (findings.length > 20) list.append(make('li', '… and ' + (findings.length - 20) + ' more'));
    el.append(list);
  }
}
function areaSelect(area) {
  active = area;
  write(prefix + 'area', area.id);
  $('#domain-select').value = area.id;
  document.querySelectorAll('nav button').forEach(b => b.setAttribute('aria-current', b.value === area.id));
  $('#name').textContent = area.name;
  $('#surface').textContent = area.surface;
  render();
}
function refURL(ref) {
  if (ref.startsWith('CWE-')) return 'https://cwe.mitre.org/data/definitions/' + ref.slice(4) + '.html';
  if (ref.startsWith('MASVS')) return 'https://mas.owasp.org/MASVS/controls/' + ref + '/';
  return 'https://owasp.org/API-Security/editions/2023/en/0x11-t10/';
}
function field(label, type, initial, onEdit) {
  const wrap = make('label', label);
  const input = make(type);
  input.value = initial;
  input.oninput = () => onEdit(input.value);
  wrap.append(input);
  return wrap;
}
function entryView(c, entry) {
  const box = make('div');
  box.className = 'entry';
  if (entry.kind === 'field') box.append(field('Field name','input',entry.name,v => {entry.name=v;save(c.id);}));
  box.append(field(entry.kind === 'field' ? 'Field value' : 'Note','textarea',entry.value,v => {entry.value=v;save(c.id);}));
  const remove = make('button','Remove ' + entry.kind);
  remove.onclick = () => {
    if ((entry.value || entry.name) && !confirm('Remove this entry?')) return;
    const entries = record(c.id).entries;
    entries.splice(entries.indexOf(entry),1);
    save(c.id); box.remove();
  };
  box.append(remove);
  return box;
}
function addEntry(owner, kind, container) {
  const entry = {kind, name:'', value:''};
  record(owner.id).entries.push(entry);
  save(owner.id);
  const box = entryView(owner, entry);
  container.append(box);
  $('input,textarea', box).focus();
}
function exerciseView(exercise) {
  const panel = make('details');
  panel.className = 'exercise';
  panel.append(make('summary', 'Run the assessment'));
  panel.append(make('h5','Prepare'), make('p',exercise.setup));
  const steps = make('ol');
  for (const step of exercise.steps) steps.append(make('li',step));
  panel.append(steps);
  if (exercise.command) {
    const block = make('pre');
    block.append(make('code',exercise.command));
    panel.append(block);
  }
  panel.append(make('h5','Interpret the result'), make('p',exercise.interpret));
  return panel;
}
function imageTransaction(change) {
  return new Promise((resolve,reject) => {
    const tx = db.transaction('images','readwrite');
    tx.oncomplete = resolve;
    tx.onabort = () => reject(tx.error);
    change(tx.objectStore('images'));
  });
}
function imageView(item) {
  const figure = make('figure'), img = make('img'), remove = make('button','Remove image');
  const url = URL.createObjectURL(item.blob);
  objectURLs.add(url);
  img.src = url; img.alt = item.name; img.loading = 'lazy';
  const link = make('a'); link.href = url; link.target = '_blank'; link.rel = 'noopener'; link.append(img);
  remove.onclick = async () => {
    if (!confirm('Remove this image?')) return;
    try {
      await imageTransaction(store => store.delete(item.key));
      attachments.set(item.id,(attachments.get(item.id) || []).filter(i => i.key !== item.key));
      render(); message('Image removed');
    } catch { message('Could not remove image', true); }
  };
  figure.append(link,make('figcaption',item.name),remove);
  return figure;
}
async function attach(c, files) {
  if (!db) {message('Image storage unavailable in this browser',true);return;}
  if (!files.length) return;
  const supported = ['image/png','image/jpeg','image/webp','image/gif'];
  if (files.some(f => !supported.includes(f.type))) {message('Choose PNG, JPEG, WebP or GIF images.',true);return;}
  busy++; message('Saving images…');
  try {
    const items = files.map((blob,index) => ({added:Date.now(),index,key:Array.from(crypto.getRandomValues(new Uint32Array(4))).join('-'),id:c.id,name:blob.name,blob}));
    await imageTransaction(store => items.forEach(i => store.add(i)));
    attachments.set(c.id,[...(attachments.get(c.id) || []),...items]);
    render(); message('Images saved on this device');
  } catch { message('Images could not be saved. Check browser storage space.',true); }
  finally {busy--;}
}
function caseView(c) {
  const node = $('#case-template').content.firstElementChild.cloneNode(true);
  const r = record(c.id);
  $('.badge',node).textContent=c.level; $('.badge',node).classList.add(c.level);
  $('.caseid',node).textContent=c.id;
  const link = $('.ref',node); link.href=refURL(c.reference); link.textContent=c.reference;
  $('h4',node).textContent=c.title; $('.procedure',node).textContent=c.procedure;
  $('.evidence p',node).textContent=c.evidence;
  if (c.exercise) $('.evidence',node).before(exerciseView(c.exercise));
  if (c.related && c.related.length) {
    const rel = make('p');
    rel.className = 'related';
    rel.append(make('strong','Related: '));
    rel.append(document.createTextNode(c.related.join(', ')));
    $('.evidence', node).after(rel);
  }

  const risk = make('div');
  risk.className = 'risk';
  const sevLabel = make('label', 'Severity');
  const sev = make('select');
  for (const opt of ['Not assessed','Critical','High','Medium','Low','Informational']) {
    const o = make('option', opt); o.value = opt; if (opt === r.severity) o.selected = true; sev.append(o);
  }
  sev.onchange = () => { r.severity = sev.value; save(c.id); };
  sevLabel.append(sev);
  const impLabel = make('label', 'Impact');
  const imp = make('input');
  imp.placeholder = 'Business or technical impact';
  imp.value = r.impact || '';
  imp.oninput = () => { r.impact = imp.value; save(c.id); };
  impLabel.append(imp);
  const retestLabel = make('label', 'Retest');
  const retest = make('input');
  retest.type = 'date';
  retest.value = r.retest || '';
  retest.onchange = () => { r.retest = retest.value; save(c.id); };
  retestLabel.append(retest);
  risk.append(sevLabel, impLabel, retestLabel);
  $('.caseactions', node).before(risk);

  const outcome = $('.outcome',node); outcome.value=r.outcome;
  const reasonBox = make('div');
  reasonBox.className = 'reason';
  const reasonLabel = make('label', 'Reason (out of scope)');
  const reason = make('input');
  reason.placeholder = 'Why this case is not applicable';
  reason.value = r.reason || '';
  reason.oninput = () => { r.reason = reason.value; save(c.id); };
  reasonLabel.append(reason);
  reasonBox.append(reasonLabel);
  reasonBox.hidden = r.outcome !== 'Not applicable';
  outcome.onchange = () => {
    r.outcome = outcome.value;
    reasonBox.hidden = outcome.value !== 'Not applicable';
    save(c.id);
    if ($('#status').value) render();
  };
  $('.caseactions', node).after(reasonBox);

  const entries = $('.entries',node);
  entries.append(...r.entries.map(e => entryView(c,e)));
  $('.addnote',node).onclick = () => addEntry(c,'note',entries);
  const upload=$('.upload',node);
  $('.addimage',node).onclick=() => upload.click();
  upload.onchange=() => {attach(c,Array.from(upload.files));upload.value='';};
  $('.images',node).append(...(attachments.get(c.id) || []).map(imageView));
  return node;
}
function render() {
  for (const url of objectURLs) URL.revokeObjectURL(url);
  objectURLs.clear();
  const root=$('#cases');
  const closed=new Set(Array.from(root.querySelectorAll('details.group:not([open])'),n=>n.dataset.group));
  root.replaceChildren();
  const groups=new Map(), term=$('#search').value.trim().toLowerCase();
  const cases = [...active.cases, ...(customCases.get(active.id) || [])];
  for (const c of cases) {
    if ($('#level').value && c.level !== $('#level').value) continue;
    if ($('#status').value && record(c.id).outcome !== $('#status').value) continue;
    if ($('#severity').value && record(c.id).severity !== $('#severity').value) continue;
    if (!JSON.stringify(c).toLowerCase().includes(term)) continue;
    if (!groups.has(c.category)) groups.set(c.category,[]);
    groups.get(c.category).push(c);
  }
  for (const [category, cases] of groups) {
    const group=make('details');group.className='group';group.dataset.group=active.id+category;
    group.open=!closed.has(group.dataset.group);
    const summary=make('summary',category);summary.append(make('small',String(cases.length)));
    group.append(summary,...cases.map(caseView));root.append(group);
  }
  if (!groups.size) root.append(make('p','No matching cases. Adjust the search or filters.'));
  metrics();
  updateFindingsSummary();
}
function literal(value) {
  const runs=String(value).match(/`+/g) || [];
  const fence=String.fromCharCode(96).repeat(Math.max(2,...runs.map(s=>s.length))+1);
  return [fence,value,fence].join('\n');
}
function dataURL(blob) {
  return new Promise((resolve,reject) => {
    const reader=new FileReader();reader.onload=()=>resolve(reader.result);reader.onerror=()=>reject(reader.error);reader.readAsDataURL(blob);
  });
}
async function exportReport() {
  if (busy) {message('Wait for the images to finish saving.',true);return;}
  const scope = $('#scope').value;
  const areas = scope === 'all' ? library : [active];
  const findingsOnly = scope === 'findings';
  const button=$('#download');button.disabled=true;button.textContent='Preparing…';
  try {
    const lines=['# PTECIAL assessment notebook','',new Date().toISOString()];
    const shared = record(notebook.id).entries;
    if (shared.length) lines.push('', '## Engagement metadata');
    for (const e of shared) lines.push('', '**' + (e.name || 'Field') + ':** ' + e.value);
    for (const area of areas) {
      lines.push('','## '+area.name);
      let category='';
      const cases = [...area.cases, ...(customCases.get(area.id) || [])];
      for (const c of cases) {
        const r=record(c.id);
        if (findingsOnly && r.outcome !== 'Finding') continue;
        if (c.category!==category) {category=c.category;lines.push('','### '+category);}
        lines.push('','#### '+c.id+' · '+c.title,'',c.level+' · ['+c.reference+']('+refURL(c.reference)+') · '+r.outcome);
        if (r.severity && r.severity !== 'Not assessed') lines.push('Severity: '+r.severity);
        if (r.impact) lines.push('Impact: '+r.impact);
        if (r.retest) lines.push('Retest: '+r.retest);
        if (r.outcome === 'Not applicable' && r.reason) lines.push('Out of scope reason: '+r.reason);
        if (c.related && c.related.length) lines.push('Related: '+c.related.join(', '));
        lines.push('',c.procedure,'','Acceptance evidence: '+c.evidence);
        if (c.exercise) {
          const {setup, steps, command, interpret} = c.exercise;
          lines.push('', setup, '', ...steps.map((s,i) => (i+1)+'. '+s));
          if (command) lines.push('',literal(command));
          lines.push('',interpret);
        }
        for (const e of r.entries) lines.push('',e.kind==='note'?'Note':'Custom field',literal(e.kind==='note'?e.value:e.name+'\n'+e.value));
        for (const image of attachments.get(c.id)||[]) lines.push('','Image',literal(image.name),'','![Evidence image]('+await dataURL(image.blob)+')');
      }
    }
    const url=URL.createObjectURL(new Blob([lines.join('\n')+'\n'],{type:'text/markdown;charset=utf-8'}));
    const a=make('a');a.href=url;a.download='ptecial-'+(areas.length===1?active.id:'all')+'-'+new Date().toISOString().slice(0,10)+'.md';
    document.body.append(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),30000);
    $('#report').close();message('Markdown downloaded');
  } catch { $('#report').close();message('Export failed. Your notebook is still here.',true); }
  finally { button.disabled=false;button.textContent='Download Markdown'; }
}
async function openImages() {
  db=await new Promise((resolve,reject)=>{
    const req=indexedDB.open('ptecial-evidence-v2',1);
    req.onupgradeneeded=()=>req.result.createObjectStore('images',{keyPath:'key'});
    req.onsuccess=()=>resolve(req.result);req.onerror=()=>reject(req.error);
  });
  const all=await new Promise((resolve,reject)=>{
    const req=db.transaction('images').objectStore('images').getAll();
    req.onsuccess=()=>resolve(req.result);req.onerror=()=>reject(req.error);
  });
  all.sort((a,b) => (a.added || 0) - (b.added || 0) || (a.index || 0) - (b.index || 0));
  for (const item of all) {
    if (!attachments.has(item.id)) attachments.set(item.id,[]);
    attachments.get(item.id).push(item);
  }
}
function checkDuplicateIds() {
  const seen = new Map();
  for (const area of library) {
    for (const c of area.cases) {
      if (seen.has(c.id)) console.warn('Duplicate case ID:', c.id, 'in', area.id, 'and', seen.get(c.id));
      else seen.set(c.id, area.id);
    }
  }
}
function loadCustomCases() {
  const raw = read(prefix + 'custom-cases');
  if (raw) try {
    const data = JSON.parse(raw);
    for (const [areaId, cases] of Object.entries(data)) customCases.set(areaId, cases);
  } catch {}
}
function saveCustomCases() {
  const data = Object.fromEntries(customCases);
  write(prefix + 'custom-cases', JSON.stringify(data));
}
function addCustomCase() {
  const title = prompt('Case title');
  if (!title) return;
  const id = 'CUSTOM-' + Date.now().toString(36).toUpperCase();
  const c = {id, category:'Custom', reference:'Engagement', title, level:'Intermediate', procedure:'', evidence:'Record evidence here.'};
  if (!customCases.has(active.id)) customCases.set(active.id, []);
  customCases.get(active.id).push(c);
  saveCustomCases();
  render();
  message('Custom case added');
}
async function start() {
  checkDuplicateIds();
  loadCustomCases();
  for (const id of [notebook.id, ...byId.keys()]) {
    const raw=read(prefix+id);
    if (raw) try {records.set(id,JSON.parse(raw));} catch {storageProblem='A saved case could not be read';}
  }
  const nb = record(notebook.id);
  if (!nb.entries.length) {
    nb.entries = [
      {kind:'field', name:'Client', value:''},
      {kind:'field', name:'Engagement ID', value:''},
      {kind:'field', name:'Tester', value:''},
      {kind:'field', name:'Start date', value:''},
      {kind:'field', name:'End date', value:''}
    ];
    save(notebook.id);
  }
  const previous=[];
  $('#fields').append(...record(notebook.id).entries.map(e => entryView(notebook,e)));
  $('#add-field').onclick = () => addEntry(notebook,'field',$('#fields'));
  $('#add-field').disabled = false;
  const addCase = make('button', '＋ Custom case');
  addCase.onclick = addCustomCase;
  $('#add-field').parentNode.append(addCase);
  for (const key of ['api','web','thick-windows','thick-linux']) {
    const raw=read('ptecial.state.'+key);
    if (raw) try {
      const old=JSON.parse(raw);
      for (const id of new Set([...Object.keys(old.notes||{}),...Object.keys(old.checked||{})])) previous.push(id+' · '+(old.checked?.[id]?'Reviewed':'Open')+'\n'+(old.notes?.[id]||''));
    } catch {storageProblem='A previous checklist could not be read';}
  }
  if (previous.length) {$('#previous').hidden=false;$('#previous pre').textContent=previous.join('\n\n');}
  try {await openImages();} catch {storageProblem='Image storage unavailable';}
  $('#total').textContent=library.length;
  for (const area of library) {
    const b=make('button');b.value=area.id;
    const code=make('span',area.id);code.className='navcode';b.append(code,make('span',area.name));
    b.onclick=()=>areaSelect(area);$('#domains').append(b);
    $('#domain-select').add(new Option(area.name,area.id));
  }
  $('#domain-select').onchange=e=>areaSelect(library.find(a=>a.id===e.target.value));
  $('#search').oninput=render;$('#status').onchange=render;$('#level').onchange=render;$('#severity').onchange=render;
  document.onkeydown=e=>{
    if(e.key==='/' && !e.ctrlKey && !e.metaKey && !/INPUT|TEXTAREA|SELECT/.test(e.target.tagName) && !$('#report').open){e.preventDefault();$('#search').focus();}
    if(e.key==='Escape' && e.target===$('#search')){$('#search').value='';render();}
  };
  $('#theme').onclick=()=>{const dark=document.documentElement.classList.toggle('dark');write(prefix+'theme',dark?'dark':'light');};
  document.documentElement.classList.toggle('dark',(read(prefix+'theme')||read('ptecial.theme'))==='dark');
  $('#export').onclick=()=>$('#report').showModal();$('#download').onclick=exportReport;
  areaSelect(library.find(a=>a.id===read(prefix+'area'))||active);
  if(storageProblem) message(storageProblem,true);
}
start();
