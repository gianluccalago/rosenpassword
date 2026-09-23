(() => {
'use strict';
const LS_KEY = 'rosen.v1';
const META_KEY = 'rosen.meta';
const ITER = 310000;
const LOCK_MS = 5 * 60 * 1000;
const CLIP_CLEAR_MS = 60 * 1000;
const CATS = ['Hospital','Pessoal','Trabalho','Financeiro','Outros'];
const $ = id => document.getElementById(id);
const enc = new TextEncoder(), dec = new TextDecoder();

let key = null;          // CryptoKey em memória enquanto aberto
let kdf = null;          // {salt (b64), iter}
let vault = null;        // {entries:[], updated}
let meta = {};           // {lastBackup, lastFileSave, dirtySince}
let fileHandle = null;
let filter = 'Todos';
let editingId = null;
let lockTimer = null;
let lockPaused = 0;      // contador: pickers/share em andamento não devem bloquear
let pendingImport = null;
let clipTimer = null;

// ---------- helpers ----------
const b64 = u8 => { let s=''; for(let i=0;i<u8.length;i++) s+=String.fromCharCode(u8[i]); return btoa(s); };
const unb64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
const uid = () => crypto.randomUUID ? crypto.randomUUID() : (Date.now().toString(36) + Math.random().toString(36).slice(2));
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
// Avisos nunca flutuam sobre o conteúdo: ocupam espaço próprio no cabeçalho do app, do modal aberto ou do cartão de bloqueio.
function toastHost(){
  const m = document.querySelector('.modal.on'); if(m) return m.querySelector('.dialog-head');
  if($('app').classList.contains('on')) return document.querySelector('.top');
  return document.querySelector('.lock-inner');
}
function toast(msg, ms){
  const t=$('toast'), host=toastHost();
  if(t.parentElement!==host){ if(host.classList.contains('lock-inner')) host.insertBefore(t, $('updateBtnLock').nextSibling); else host.appendChild(t); }
  document.querySelectorAll('.toasting').forEach(h=>h.classList.remove('toasting'));
  t.textContent=msg; t.classList.remove('long'); t.classList.add('on');
  if(t.scrollWidth > t.clientWidth + 1) t.classList.add('long');
  else host.classList.add('toasting');
  const sr=$('srLive'); sr.textContent=''; setTimeout(()=>{ sr.textContent=msg; }, 30);
  clearTimeout(t._t); t._t=setTimeout(()=>{ t.classList.remove('on','long'); host.classList.remove('toasting'); }, ms||2200);
}
function fmt(ts){ if(!ts) return null; const d=new Date(ts); return d.toLocaleDateString('pt-BR')+' '+d.toLocaleTimeString('pt-BR',{hour:'2-digit',minute:'2-digit'}); }
function daysAgo(ts){ return ts ? (Date.now()-ts)/86400000 : Infinity; }
const isTouch = matchMedia('(pointer:coarse)').matches;
const isStandalone = matchMedia('(display-mode: standalone)').matches || navigator.standalone === true;
const isIOS = /iPad|iPhone|iPod/.test(navigator.userAgent) || (navigator.platform==='MacIntel' && navigator.maxTouchPoints>1);
const DRAFT_KEY = 'rosen.draft';
let shareFailed = false;

// ---------- pré-requisitos ----------
function fatal(msg){ const f=$('fatal'); f.textContent=msg; f.classList.remove('hidden'); $('lockScreen').classList.add('hidden'); }
if (!window.crypto || !crypto.subtle) {
  fatal('Este navegador não oferece criptografia segura (WebCrypto), então o Rosen não pode abrir nem criar um cofre. Abra em Chrome, Edge, Firefox ou Safari atualizados e por um endereço https ou localhost.');
  return;
}

// ---------- armazenamento (localStorage com fallback em memória) ----------
const mem = {};
let storageOk = true;
const store = {
  get(k){ try { return localStorage.getItem(k); } catch(e){ storageOk=false; return mem[k] ?? null; } },
  set(k,v){
    try { localStorage.setItem(k, v); return true; }
    catch(e){
      mem[k]=v;
      if (e && (e.name==='QuotaExceededError' || e.name==='NS_ERROR_DOM_QUOTA_REACHED' || e.code===22 || e.code===1014)) {
        toast('O armazenamento do navegador está cheio. O que você fez não foi gravado: baixe um backup agora e libere espaço nas configurações do site.', 6000);
      } else {
        storageOk=false;
        toast('O navegador não permite gravar dados (modo privado ou bloqueio de armazenamento). Nada será mantido ao fechar: baixe um backup.', 6000);
      }
      return false;
    }
  }
};
try { meta = JSON.parse(store.get(META_KEY) || '{}') || {}; } catch(e){ meta = {}; }
function saveMeta(){ store.set(META_KEY, JSON.stringify(meta)); }
(function probeStorage(){
  try { const t='rosen.probe'; localStorage.setItem(t,'1'); localStorage.removeItem(t); }
  catch(e){ storageOk=false; const n=$('storageNotice'); n.textContent='O armazenamento deste navegador está indisponível (modo privado ou bloqueado). Você pode usar o Rosen, mas nada ficará salvo ao fechar. Saia do modo privado ou mantenha um backup .rosen.'; n.classList.remove('hidden'); }
})();

// ---------- crypto ----------
async function deriveKey(pw, saltU8, iter){
  const base = await crypto.subtle.importKey('raw', enc.encode(pw), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({name:'PBKDF2', salt:saltU8, iterations:iter, hash:'SHA-256'}, base, {name:'AES-GCM', length:256}, false, ['encrypt','decrypt']);
}
async function encryptVault(k, obj){
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({name:'AES-GCM', iv}, k, enc.encode(JSON.stringify(obj)));
  return {v:1, app:'rosen', kdf:{salt:kdf.salt, iter:kdf.iter}, iv:b64(iv), ct:b64(new Uint8Array(ct)), updated:obj.updated};
}
function validBlob(b){
  return !!(b && typeof b==='object' && b.app==='rosen' && (b.v===1 || b.v===undefined) && b.kdf && typeof b.kdf.salt==='string' && Number.isInteger(b.kdf.iter) && b.kdf.iter>0 && typeof b.iv==='string' && typeof b.ct==='string');
}
async function decryptBlob(blob, pw){
  if(!validBlob(blob)) throw new Error('formato');
  const k = await deriveKey(pw, unb64(blob.kdf.salt), blob.kdf.iter);
  const pt = await crypto.subtle.decrypt({name:'AES-GCM', iv:unb64(blob.iv)}, k, unb64(blob.ct));
  const data = JSON.parse(dec.decode(pt));
  if(!data || typeof data!=='object') throw new Error('formato');
  data.entries = Array.isArray(data.entries) ? data.entries : [];
  return {k, data};
}

// ---------- persistência ----------
async function persist(){
  if(!key || !vault) return;
  vault.updated = Date.now();
  let str;
  try { str = JSON.stringify(await encryptVault(key, vault)); }
  catch(e){ toast('Falha ao criptografar os dados. Nada foi gravado. Feche e abra o Rosen novamente.', 5000); return; }
  store.set(LS_KEY, str);
  meta.dirtySince = meta.dirtySince || Date.now();
  if (fileHandle) {
    try {
      const w = await fileHandle.createWritable();
      await w.write(str); await w.close();
      meta.lastFileSave = Date.now();
    } catch(e){
      if(e && e.name==='NotAllowedError') toast('Permissão para gravar no arquivo vinculado foi negada. Vincule o arquivo de novo ou baixe um backup.', 5000);
      else toast('Não consegui gravar no arquivo vinculado (o arquivo pode ter sido movido). Baixe um backup.', 5000);
    }
  }
  saveMeta();
  renderStatus();
}
function backupName(){
  const d = new Date(), pad = n => String(n).padStart(2,'0');
  return `rosen-${d.getFullYear()}-${pad(d.getMonth()+1)}-${pad(d.getDate())}_${pad(d.getHours())}${pad(d.getMinutes())}.rosen`;
}
function markBackup(){ meta.lastBackup = Date.now(); meta.dirtySince = null; saveMeta(); renderStatus(); }
function exportBackup(){
  const str = store.get(LS_KEY);
  if(!str){ toast('Nada para exportar ainda.'); return; }
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([str], {type:'application/json'}));
  a.download = backupName(); document.body.appendChild(a); a.click(); a.remove();
  setTimeout(()=>URL.revokeObjectURL(a.href), 4000);
  markBackup();
  toast('Backup baixado');
}
function shareFile(){
  const str = store.get(LS_KEY); if(!str) return null;
  try { return new File([str], backupName(), {type:'application/json'}); } catch(e){ return null; }
}
function canShare(){
  const f = shareFile();
  return !!(f && navigator.share && navigator.canShare && navigator.canShare({files:[f]}));
}
async function shareBackup(){
  const f = shareFile();
  if(!f || !canShare()){ toast('Compartilhar arquivos não está disponível neste navegador. Use "Baixar backup".'); return; }
  const resume = pauseLock();
  try {
    await navigator.share({files:[f], title:'Backup do Rosen'});
    markBackup(); toast('Backup compartilhado');
  } catch(e){
    if(!e || e.name!=='AbortError'){ shareFailed=true; toast('Não foi possível compartilhar o backup. Abra o menu de novo e use "Baixar backup".', 4000); }
  } finally { resume(); }
}

// File System Access API (Chrome/Edge desktop). O handle fica no IndexedDB para reconectar depois.
const hasFSA = 'showSaveFilePicker' in window;
function idb(){ return new Promise((res,rej)=>{ let r; try { r=indexedDB.open('rosen-fs',1); } catch(e){ return rej(e); } r.onupgradeneeded=()=>r.result.createObjectStore('kv'); r.onsuccess=()=>res(r.result); r.onerror=()=>rej(r.error); }); }
async function idbSet(k,v){ const db=await idb(); return new Promise((res,rej)=>{ const t=db.transaction('kv','readwrite'); t.objectStore('kv').put(v,k); t.oncomplete=res; t.onerror=()=>rej(t.error); }); }
async function idbGet(k){ const db=await idb(); return new Promise((res,rej)=>{ const t=db.transaction('kv','readonly'); const r=t.objectStore('kv').get(k); r.onsuccess=()=>res(r.result); r.onerror=()=>rej(r.error); }); }
async function linkFile(){
  if(!hasFSA){ toast('Este navegador não permite gravação automática em arquivo. Use o backup manual.'); return; }
  const resume = pauseLock();
  try {
    fileHandle = await window.showSaveFilePicker({suggestedName:'meu-rosen.rosen', types:[{description:'Rosen criptografado', accept:{'application/json':['.rosen']}}]});
    try { await idbSet('handle', fileHandle); } catch(e){ toast('O arquivo foi vinculado só nesta sessão: o navegador não deixou lembrar dele.', 4000); }
    await persist();
    toast('Arquivo vinculado. Toda alteração será gravada nele.');
  } catch(e){
    if(e && e.name==='NotAllowedError') toast('Permissão de acesso ao arquivo negada. Permita o acesso no navegador ou use o backup manual.', 5000);
    else if(!e || e.name!=='AbortError') toast('Não foi possível vincular o arquivo. Use o backup manual.', 4000);
  } finally { resume(); }
}
async function reconnectFile(){
  if(!hasFSA) return;
  const resume = pauseLock();
  try {
    const h = await idbGet('handle'); if(!h) return;
    let p = await h.queryPermission({mode:'readwrite'});
    if(p!=='granted') p = await h.requestPermission({mode:'readwrite'});
    if(p==='granted'){ fileHandle = h; renderStatus(); }
    else toast('Sem permissão para o arquivo vinculado. As alterações ficam só neste navegador até você vincular de novo.', 5000);
  } catch(e){ /* sem handle ou API indisponível */ }
  finally { resume(); }
}

// ---------- força / gerador ----------
function strength(pw){
  let s=0; if(pw.length>=10) s++; if(pw.length>=14) s++; if(/[a-z]/.test(pw)&&/[A-Z]/.test(pw)) s++; if(/\d/.test(pw)) s++; if(/[^\w]/.test(pw)) s++; if(pw.length>=20) s++;
  return Math.min(s,5);
}
function meter(el, pw){
  const s=strength(pw); el.style.width=(pw?Math.max(8,s*20):0)+'%';
  el.style.background = s<=1?'var(--danger)': s<=3?'var(--pink2)':'var(--ok)';
}
function rnd(n){ return crypto.getRandomValues(new Uint32Array(1))[0] % n; }
function genPassword(len, sym){
  const sets = ['abcdefghijkmnopqrstuvwxyz','ABCDEFGHJKLMNPQRSTUVWXYZ','23456789'];
  if(sym) sets.push('!@#$%&*?-_+=');
  const all = sets.join('');
  const out = [];
  for(const s of sets) out.push(s[rnd(s.length)]);
  while(out.length<len) out.push(all[rnd(all.length)]);
  for(let i=out.length-1;i>0;i--){ const j=rnd(i+1); [out[i],out[j]]=[out[j],out[i]]; }
  return out.join('');
}

// ---------- área de transferência ----------
async function copyText(txt, btn){
  let ok = false;
  try { await navigator.clipboard.writeText(txt); ok = true; }
  catch(e){
    try { const ta=document.createElement('textarea'); ta.value=txt; ta.setAttribute('readonly',''); ta.style.position='fixed'; ta.style.opacity='0'; document.body.appendChild(ta); ta.select(); ok=document.execCommand('copy'); ta.remove(); } catch(e2){ ok=false; }
  }
  if(!ok){ toast('Não foi possível copiar. Toque em mostrar e selecione o texto manualmente.'); return; }
  toast('Copiado. Será limpo em 60 s.');
  if(btn){ btn.classList.add('copied'); setTimeout(()=>btn.classList.remove('copied'),1200); }
  scheduleClipClear(txt);
}
function scheduleClipClear(txt){
  clearTimeout(clipTimer);
  clipTimer = setTimeout(async ()=>{
    // Só limpa se ainda for o que copiamos. Nunca pede permissão: só lê se já estiver concedida.
    try {
      if(!navigator.clipboard || !navigator.clipboard.readText || !navigator.permissions) return;
      const st = await navigator.permissions.query({name:'clipboard-read'});
      if(st.state !== 'granted') return;
      const cur = await navigator.clipboard.readText();
      if(cur === txt) await navigator.clipboard.writeText('');
    } catch(e){ /* sem permissão ou API: não faz nada */ }
  }, CLIP_CLEAR_MS);
}

// ---------- bloqueio ----------
function pauseLock(){ lockPaused++; let done=false; return ()=>{ if(!done){ done=true; lockPaused=Math.max(0,lockPaused-1); if(key) bumpLock(); } }; }
function showLock(msg){
  if(key && kdf && vault && $('entryModal').classList.contains('on')){
    const d = readEntryForm();
    if(draftWorthKeeping(d)) stashDraft(key, kdf, d);
  }
  key=null; vault=null; kdf=null; editingId=null; pendingImport=null; clearTimeout(lockTimer);
  closeMenu(); closeAllModals();
  ['entryForm','pwForm','importForm'].forEach(f=>$(f).reset()); setEye('fPw', false); $('orgList').innerHTML='';
  $('list').innerHTML=''; $('q').value='';
  $('app').classList.remove('on'); $('lockScreen').classList.remove('hidden');
  const has = !!store.get(LS_KEY);
  $('setupView').classList.toggle('hidden', has); $('unlockView').classList.toggle('hidden', !has);
  $('unlockPw').value=''; $('unlockErr').textContent=''; $('setupErr').textContent='';
  if(msg) toast(msg);
  setTimeout(()=> (has?$('unlockPw'):$('setupPw')).focus(), 50);
}
function showApp(){
  $('lockScreen').classList.add('hidden'); $('app').classList.add('on');
  filter='Todos';
  render(); renderStatus(); bumpLock();
  askPersistentStorage();
}
// Pede ao navegador para não apagar os dados sob falta de espaço. Sem efeito visível se negado.
function askPersistentStorage(){
  try { if(navigator.storage && navigator.storage.persist) navigator.storage.persisted().then(p=> p || navigator.storage.persist()).catch(()=>{}); } catch(e){}
}

// ---------- rascunho do cadastro (sobrevive ao bloqueio, sempre criptografado) ----------
function readEntryForm(){ return {id:editingId, name:$('fName').value, cat:$('fCat').value, org:$('fOrg').value, login:$('fLogin').value, pw:$('fPw').value, url:$('fUrl').value, notes:$('fNotes').value}; }
function draftWorthKeeping(d){
  const cur = d.id ? vault.entries.find(x=>x.id===d.id) : null;
  if(cur) return ['name','cat','org','login','pw','url','notes'].some(k => (d[k]||'') !== (cur[k]||''));
  return !!(d.name||d.org||d.login||d.pw||d.url||d.notes);
}
async function stashDraft(k, s, d){
  try {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = await crypto.subtle.encrypt({name:'AES-GCM', iv}, k, enc.encode(JSON.stringify(d)));
    store.set(DRAFT_KEY, JSON.stringify({salt:s.salt, iv:b64(iv), ct:b64(new Uint8Array(ct))}));
  } catch(e){ /* sem rascunho: o cadastro já salvo não é afetado */ }
}
function dropDraft(){ delete mem[DRAFT_KEY]; try { localStorage.removeItem(DRAFT_KEY); } catch(e){} }
async function restoreDraft(){
  const str = store.get(DRAFT_KEY); if(!str) return;
  dropDraft();
  try {
    const d = JSON.parse(str);
    if(!key || !kdf || !vault || d.salt!==kdf.salt) return;
    const pt = await crypto.subtle.decrypt({name:'AES-GCM', iv:unb64(d.iv)}, key, unb64(d.ct));
    const f = JSON.parse(dec.decode(pt));
    openEntry(f.id && vault.entries.some(x=>x.id===f.id) ? f.id : null, f);
    toast('O cadastro que estava aberto foi recuperado. Confira e toque em Salvar.', 4000);
  } catch(e){ /* rascunho de outra senha mestre ou corrompido: descartado */ }
}
function bumpLock(){ clearTimeout(lockTimer); if(key) lockTimer=setTimeout(()=>{ if(lockPaused) { bumpLock(); return; } showLock('Rosen bloqueado por inatividade'); }, LOCK_MS); }
['click','keydown','mousemove','touchstart','scroll'].forEach(ev=>document.addEventListener(ev, ()=>{ if(key) bumpLock(); }, {passive:true}));
// No celular (ou instalado), sair para o background bloqueia na hora; no desktop vale o timer de 5 min.
document.addEventListener('visibilitychange', ()=>{
  if(document.visibilityState==='hidden'){
    if(key && !lockPaused && (isTouch || isStandalone)) showLock();
  } else if(document.visibilityState==='visible'){
    if(key) bumpLock();
    if(swReg) swReg.update().catch(()=>{});
  }
});
window.addEventListener('pagehide', ()=>{ if(key && !lockPaused && (isTouch || isStandalone)) showLock(); });

// ---------- criar / abrir ----------
async function setup(){
  const pw=$('setupPw').value, pw2=$('setupPw2').value, err=$('setupErr');
  err.textContent='';
  if(pw.length<10){ err.textContent='A senha mestre precisa ter pelo menos 10 caracteres.'; return; }
  if(pw!==pw2){ err.textContent='As senhas não coincidem. Digite a mesma senha nos dois campos.'; return; }
  const btn=$('setupBtn'); btn.disabled=true; btn.textContent='Criando';
  try {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    kdf = {salt:b64(salt), iter:ITER};
    key = await deriveKey(pw, salt, ITER);
    vault = {entries:[], updated:Date.now()};
    meta = {}; saveMeta(); dropDraft();
    await persist();
    $('setupPw').value=''; $('setupPw2').value=''; meter($('setupMeter'),'');
    showApp();
    toast('Rosen criado. Faça um backup assim que cadastrar as primeiras senhas.', 4000);
  } catch(e){ key=null; vault=null; err.textContent='Não foi possível criar o cofre: o navegador recusou a operação de criptografia. Recarregue a página e tente de novo.'; }
  btn.disabled=false; btn.textContent='Criar Rosen';
}
async function unlock(){
  const pw=$('unlockPw').value, err=$('unlockErr'); err.textContent='';
  const str=store.get(LS_KEY); if(!str){ showLock(); return; }
  const btn=$('unlockBtn'); btn.disabled=true; btn.textContent='Abrindo';
  let blob=null;
  try { blob = JSON.parse(str); } catch(e){ blob=null; }
  if(!validBlob(blob)){
    err.textContent='Os dados salvos neste navegador estão corrompidos ou em formato desconhecido. Restaure de um backup .rosen.';
    btn.disabled=false; btn.textContent='Abrir Rosen'; return;
  }
  try {
    const {k, data} = await decryptBlob(blob, pw);
    key=k; kdf=blob.kdf; vault=data;
    $('unlockPw').value='';
    showApp();
    await restoreDraft();
    reconnectFile();
  } catch(e){ err.textContent='Senha mestre incorreta. Verifique maiúsculas e o teclado e tente de novo.'; }
  btn.disabled=false; btn.textContent='Abrir Rosen';
}

// ---------- restaurar ----------
function startImport(){ $('fileInput').value=''; const resume=pauseLock(); $('fileInput')._resume=resume; setTimeout(resume, 120000); $('fileInput').click(); }
window.addEventListener('focus', ()=>{ const r=$('fileInput')._resume; if(r){ setTimeout(r, 1500); } });
$('fileInput').addEventListener('change', async ()=>{
  const r=$('fileInput')._resume; if(r) r();
  const f=$('fileInput').files[0]; if(!f) return;
  let blob=null;
  try { blob = JSON.parse(await f.text()); } catch(e){ blob=null; }
  if(!validBlob(blob)){ toast('Este arquivo não é um backup do Rosen (esperado um .rosen gerado pelo próprio app). Escolha outro arquivo.', 5000); return; }
  pendingImport = blob;
  let local=null; try { local=JSON.parse(store.get(LS_KEY)||'null'); } catch(e){ local=null; }
  let warn='Isso substitui o que está salvo neste aparelho pelo conteúdo do backup.';
  if(validBlob(local)){
    const n = vault ? vault.entries.length : null;
    warn = 'Isso substitui ' + (n!==null ? `as ${n} senha(s) salvas neste aparelho` : 'o cofre salvo neste aparelho') + ' pelo conteúdo do backup.';
    if(blob.updated && local.updated && blob.updated < local.updated) warn += ` Atenção: este backup (${fmt(blob.updated)}) é mais antigo que os dados daqui (${fmt(local.updated)}). O que foi cadastrado ou alterado depois dele será perdido. Se não tiver certeza, cancele e faça antes um backup dos dados atuais.`;
  }
  $('importWarn').textContent = warn;
  $('importInfo').textContent = `Arquivo: ${f.name}${blob.updated?' (salvo em '+fmt(blob.updated)+')':''}`;
  $('impPw').value=''; $('impErr').textContent='';
  openModal('importModal', 'impPw');
});
$('impCancel').onclick=()=>{ closeModal('importModal'); pendingImport=null; };
$('importForm').addEventListener('submit', async ev=>{
  ev.preventDefault();
  if(!pendingImport) return;
  const pw=$('impPw').value, err=$('impErr'); err.textContent='';
  const btn=$('impOk'); btn.disabled=true;
  try {
    const {k, data} = await decryptBlob(pendingImport, pw);
    key=k; kdf=pendingImport.kdf; vault=data;
    const saved = store.set(LS_KEY, JSON.stringify(pendingImport));
    meta.lastBackup = pendingImport.updated || Date.now(); meta.dirtySince=null; saveMeta(); dropDraft();
    closeModal('importModal'); pendingImport=null;
    showApp(); toast(saved ? `Restaurado: ${vault.entries.length} senha(s)` : `Aberto com ${vault.entries.length} senha(s), mas não foi possível gravar neste navegador.`, 4000);
    reconnectFile();
  } catch(e){ err.textContent='Senha mestre incorreta para este backup. Use a senha que valia quando ele foi gerado.'; }
  btn.disabled=false;
});

// ---------- trocar senha mestre ----------
$('changePwBtn').onclick=()=>{ closeMenu(); ['cpOld','cpNew','cpNew2'].forEach(i=>$(i).value=''); $('cpErr').textContent=''; meter($('cpMeter'),''); openModal('pwModal','cpOld'); };
$('cpCancel').onclick=()=>closeModal('pwModal');
$('cpNew').addEventListener('input', e=>meter($('cpMeter'), e.target.value));
$('pwForm').addEventListener('submit', async ev=>{
  ev.preventDefault();
  const o=$('cpOld').value, n=$('cpNew').value, n2=$('cpNew2').value, err=$('cpErr'); err.textContent='';
  if(n.length<10){ err.textContent='A nova senha precisa ter pelo menos 10 caracteres.'; return; }
  if(n!==n2){ err.textContent='As novas senhas não coincidem.'; return; }
  const btn=$('cpSave'); btn.disabled=true;
  try {
    let blob=null; try { blob=JSON.parse(store.get(LS_KEY)); } catch(e){}
    await decryptBlob(blob, o);
  } catch(e){ err.textContent='Senha atual incorreta.'; btn.disabled=false; return; }
  try {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    kdf={salt:b64(salt), iter:ITER}; key=await deriveKey(n, salt, ITER);
    await persist();
    closeModal('pwModal'); toast('Senha mestre trocada. Baixe um novo backup.', 4000);
  } catch(e){ err.textContent='Falha ao gerar a nova chave. A senha antiga continua valendo.'; }
  btn.disabled=false;
});

// ---------- modais ----------
function openModal(id, focusId){ $(id).classList.add('on'); document.body.style.overflow='hidden'; if(focusId) setTimeout(()=>{ if(!$(id).contains(document.activeElement)) $(focusId).focus(); },60); }
function closeModal(id){ $(id).classList.remove('on'); if(!document.querySelector('.modal.on')) document.body.style.overflow=''; }
function closeAllModals(){ document.querySelectorAll('.modal.on').forEach(m=>m.classList.remove('on')); document.body.style.overflow=''; }

// ---------- registros ----------
function openEntry(id, draft){
  editingId=id||null;
  const cur = id ? vault.entries.find(x=>x.id===id) : null;
  const e = draft || cur;
  $('entryTitle').textContent = cur ? 'Editar senha' : 'Nova senha';
  $('fName').value=e?.name||''; $('fCat').value=CATS.includes(e?.cat)?e.cat:'Hospital'; $('fOrg').value=e?.org||'';
  $('fLogin').value=e?.login||''; $('fPw').value=e?.pw||''; setEye('fPw', false); $('fUrl').value=e?.url||''; $('fNotes').value=e?.notes||'';
  $('deleteBtn').classList.toggle('hidden', !cur); $('entryErr').textContent='';
  $('orgList').innerHTML = [...new Set(vault.entries.map(x=>x.org).filter(Boolean))].map(o=>`<option value="${esc(o)}">`).join('');
  openModal('entryModal', 'fName');
  $('entryForm').querySelector('.dialog-body').scrollTop=0;
}
function closeEntry(){ closeModal('entryModal'); editingId=null; }
$('addBtn').onclick=()=>openEntry(null);
$('addBtnTop').onclick=()=>openEntry(null);
$('cancelBtn').onclick=closeEntry;
$('entryClose').onclick=closeEntry;
$('genBtn').onclick=()=>{ $('fPw').value=genPassword(Math.min(64,Math.max(8,+$('genLen').value||16)), $('genSym').checked); setEye('fPw', true); };
$('entryForm').addEventListener('submit', async ev=>{
  ev.preventDefault();
  if(!vault) return;
  const name=$('fName').value.trim(), err=$('entryErr'); err.textContent='';
  if(!name){ err.textContent='Informe do que é esta senha.'; $('fName').focus(); return; }
  const data={name, cat:$('fCat').value, org:$('fOrg').value.trim(), login:$('fLogin').value, pw:$('fPw').value, url:$('fUrl').value.trim(), notes:$('fNotes').value.trim(), updated:Date.now()};
  if(editingId){ const cur=vault.entries.find(x=>x.id===editingId); if(cur) Object.assign(cur, data); else vault.entries.push({id:uid(), created:Date.now(), ...data}); }
  else { vault.entries.push({id:uid(), created:Date.now(), ...data}); }
  await persist(); closeEntry(); render(); toast('Salvo');
});
$('deleteBtn').onclick=async ()=>{
  const e=vault.entries.find(x=>x.id===editingId); if(!e) return;
  if(!confirm(`Excluir "${e.name}"? Não dá para desfazer.`)) return;
  vault.entries=vault.entries.filter(x=>x.id!==editingId);
  await persist(); closeEntry(); render(); toast('Excluída');
};

// ---------- render ----------
function renderStatus(){
  if(!vault) return;
  const n=vault.entries.length;
  $('txtCount').textContent = n?`${n} senha${n>1?'s':''}`:'';
  $('dotLocal').className = storageOk?'dot ok':'dot bad';
  $('txtLocal').textContent = storageOk?'Salvo neste navegador':'Não está sendo salvo (armazenamento indisponível)';
  if(fileHandle){ $('dotFile').className='dot ok'; $('txtFile').textContent='Arquivo vinculado'+(meta.lastFileSave?', gravado '+fmt(meta.lastFileSave):''); }
  else { $('dotFile').className='dot'; $('txtFile').textContent= hasFSA?'Sem arquivo vinculado':'Gravação automática indisponível neste navegador'; }
  const d=daysAgo(meta.lastBackup);
  let sum, sumCls;
  if(!meta.lastBackup){ $('dotBackup').className='dot bad'; $('txtBackup').textContent='Nenhum backup baixado'; sum='Sem backup'; sumCls='bad'; }
  else { $('dotBackup').className= d>14?'dot warn':'dot ok'; $('txtBackup').textContent='Último backup '+fmt(meta.lastBackup)+(meta.dirtySince?' (há alterações desde então)':''); sum='Backup '+fmt(meta.lastBackup)+(meta.dirtySince?', com alterações':''); sumCls= d>14?'warn':'ok'; }
  if(fileHandle){ sum='Arquivo vinculado'; sumCls='ok'; }
  if(!storageOk){ sum='Não está sendo salvo'; sumCls='bad'; }
  $('dotSum').className='dot '+sumCls;
  $('txtSum').textContent = (n?`${n} senha${n>1?'s':''}. `:'') + sum;
  const b=$('banner'); b.className='banner hidden'; b.innerHTML='';
  if(!fileHandle){
    if(n>0 && !meta.lastBackup){ b.className='banner'; b.innerHTML='<span class="grow">Suas senhas estão salvas só neste navegador. Se o histórico for limpo ou o aparelho trocar, elas somem. Faça um backup agora.</span><button class="btn sm primary" id="bannerExport" type="button">Fazer backup</button>'; }
    else if(n>0 && meta.dirtySince){ b.className='banner warn'; b.innerHTML='<span class="grow">Há senhas cadastradas ou alteradas que ainda não estão em nenhum backup.</span><button class="btn sm" id="bannerExport" type="button">Fazer backup</button>'; }
    const be=$('bannerExport'); if(be) be.onclick=()=> canShare() && isTouch ? shareBackup() : exportBackup();
  }
}
function render(){
  if(!vault) return;
  const q=$('q').value.trim().toLowerCase();
  const chips=$('chips'); const cats=['Todos',...CATS.filter(c=>vault.entries.some(e=>e.cat===c))];
  if(!cats.includes(filter)) filter='Todos';
  chips.innerHTML = cats.map(c=>`<button class="chip ${filter===c?'on':''}" type="button" data-cat="${esc(c)}" aria-pressed="${filter===c}">${esc(c)}${c==='Todos'?'':' ('+vault.entries.filter(e=>e.cat===c).length+')'}</button>`).join('');
  chips.querySelectorAll('.chip').forEach(b=>b.onclick=()=>{ filter=b.dataset.cat; render(); });
  let items = vault.entries.filter(e=>filter==='Todos'||e.cat===filter);
  if(q) items=items.filter(e=>[e.name,e.org,e.login,e.cat,e.url,e.notes].join(' ').toLowerCase().includes(q));
  const list=$('list');
  if(!vault.entries.length){ list.innerHTML='<div class="empty"><h2>Rosen vazio</h2>Cadastre a primeira senha pelo botão "Nova senha".</div>'; return; }
  if(!items.length){ list.innerHTML='<div class="empty">Nada encontrado para essa busca.</div>'; return; }
  const groups=new Map();
  for(const e of items.sort((a,b)=>(a.org||'').localeCompare(b.org||'')||String(a.name||'').localeCompare(String(b.name||'')))){
    const g = e.org ? `${e.org}` : (e.cat==='Hospital'?'Hospitais (sem instituição)':(e.cat||'Outros'));
    if(!groups.has(g)) groups.set(g,[]); groups.get(g).push(e);
  }
  list.innerHTML=[...groups.entries()].map(([g,es])=>`
    <section class="group"><h2>${esc(g)} <small>${es.length}</small></h2><div class="grid">${es.map(card).join('')}</div></section>`).join('');
  list.querySelectorAll('[data-copy]').forEach(b=>b.onclick=()=>{ const e=vault.entries.find(x=>x.id===b.dataset.id); if(e) copyText(b.dataset.copy==='pw'?(e.pw||''):(e.login||''), b); });
  list.querySelectorAll('[data-toggle]').forEach(b=>b.onclick=()=>{
    const v=b.parentElement.querySelector('.v'); const e=vault.entries.find(x=>x.id===b.dataset.toggle); if(!e) return;
    const masked=v.classList.toggle('masked'); v.textContent= masked?'••••••••••':e.pw;
    b.setAttribute('aria-label', masked?'Mostrar senha':'Ocultar senha'); b.setAttribute('aria-pressed', String(!masked));
  });
  list.querySelectorAll('[data-edit]').forEach(b=>b.onclick=()=>openEntry(b.dataset.edit));
}
const I = {
  copy:'<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><rect x="9" y="9" width="11" height="11" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h10"/></svg>',
  eye:'<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M2 12s3.5-6 10-6 10 6 10 6-3.5 6-10 6S2 12 2 12z"/><circle cx="12" cy="12" r="3"/></svg>',
  edit:'<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M12 20h9"/><path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4z"/></svg>'
};
function card(e){
  const url = e.url && /^https?:\/\//i.test(e.url) ? `<a href="${esc(e.url)}" target="_blank" rel="noopener noreferrer">${esc(e.url.replace(/^https?:\/\//,'').replace(/\/$/,''))}</a>` : '';
  const org = [esc(e.cat), url].filter(Boolean).join(' · ');
  const id = esc(e.id);
  return `<article class="card">
    <div class="card-head"><div class="card-title"><h3>${esc(e.name)}</h3><div class="org">${org}</div></div><button class="ic" type="button" data-edit="${id}" aria-label="Editar ${esc(e.name)}">${I.edit}</button></div>
    <div class="row"><span class="k">Login</span><span class="v" title="${e.login?esc(e.login):''}">${e.login?esc(e.login):'<span class="none">—</span>'}</span>${e.login?`<button class="ic" type="button" data-copy="login" data-id="${id}" aria-label="Copiar login">${I.copy}</button>`:''}</div>
    <div class="row"><span class="k">Senha</span><span class="v masked">${e.pw?'••••••••••':'<span class="none">—</span>'}</span>${e.pw?`<button class="ic" type="button" data-toggle="${id}" aria-label="Mostrar senha" aria-pressed="false">${I.eye}</button><button class="ic" type="button" data-copy="pw" data-id="${id}" aria-label="Copiar senha">${I.copy}</button>`:''}</div>
    ${e.notes?`<div class="notes">${esc(e.notes)}</div>`:''}
  </article>`;
}

// ---------- ligações ----------
function setEye(id, show){ const i=$(id); i.type = show?'text':'password'; const b=document.querySelector(`[data-eye="${id}"]`); if(b){ b.setAttribute('aria-pressed', String(show)); b.setAttribute('aria-label', show?'Ocultar senha':'Mostrar senha'); } }
document.querySelectorAll('[data-eye]').forEach(b=>b.onclick=()=>{ const i=$(b.dataset.eye); setEye(b.dataset.eye, i.type==='password'); });
$('setupPw').addEventListener('input', e=>meter($('setupMeter'), e.target.value));
$('setupView').addEventListener('submit', ev=>{ ev.preventDefault(); setup(); });
$('unlockView').addEventListener('submit', ev=>{ ev.preventDefault(); unlock(); });
$('setupImportBtn').onclick=startImport; $('unlockImportBtn').onclick=startImport; $('importBtn').onclick=()=>{ closeMenu(); startImport(); };
$('exportBtn').onclick=()=>{ closeMenu(); exportBackup(); };
$('shareBtn').onclick=()=>{ closeMenu(); shareBackup(); };
$('linkFileBtn').onclick=()=>{ closeMenu(); linkFile(); };
$('lockBtn').onclick=()=>{ closeMenu(); showLock(); };
$('q').addEventListener('input', render);
$('menuBtn').onclick=e=>{ e.stopPropagation(); const open=$('menu').classList.toggle('open'); $('menuBtn').setAttribute('aria-expanded', String(open)); if(open){ const sh=canShare(); $('shareBtn').classList.toggle('hidden', !sh); $('exportBtn').classList.toggle('hidden', isIOS && sh && !shareFailed); } };
function closeMenu(){ $('menu').classList.remove('open'); $('menuBtn').setAttribute('aria-expanded','false'); }
document.addEventListener('click', e=>{ if(!$('menu').contains(e.target)) closeMenu(); });
$('statusSum').onclick=()=>{ const open=$('status').classList.toggle('open'); $('statusSum').setAttribute('aria-expanded', String(open)); };
document.addEventListener('keydown', e=>{
  if(e.key!=='Escape') return;
  if($('menu').classList.contains('open')){ closeMenu(); return; }
  if($('entryModal').classList.contains('on')) closeEntry();
  if($('pwModal').classList.contains('on')) closeModal('pwModal');
  if($('importModal').classList.contains('on')){ closeModal('importModal'); pendingImport=null; }
});
if(isIOS){ $('fileInput').removeAttribute('accept'); $('linkFileBtn').classList.add('hidden'); $('linkFileDesc').classList.add('hidden'); }
if(isIOS && !isStandalone) $('installNotice').classList.remove('hidden');
if(!hasFSA){ $('linkFileDesc').textContent='Disponível apenas no Chrome ou Edge de computador. Aqui, use o backup manual.'; }
if(isTouch){ $('exportDesc').textContent='Arquivo .rosen. Só abre com a senha mestre. No iPhone, prefira "Compartilhar backup" e salve em Arquivos (iCloud Drive).'; }
window.addEventListener('beforeunload', e=>{ if(key && vault && vault.entries.length && !fileHandle && !meta.lastBackup){ e.preventDefault(); e.returnValue=''; } });

// ---------- service worker / atualização ----------
let swReg = null;
let updateRequested = false;
if('serviceWorker' in navigator && (location.protocol==='https:' || location.hostname==='localhost' || location.hostname==='127.0.0.1')){
  window.addEventListener('load', async ()=>{
    try {
      swReg = await navigator.serviceWorker.register('sw.js');
      const offer = w => { if(!w) return; w.addEventListener('statechange', ()=>{ if(w.state==='installed' && navigator.serviceWorker.controller) showUpdate(swReg); }); };
      if(swReg.waiting && navigator.serviceWorker.controller) showUpdate(swReg);
      offer(swReg.installing);
      swReg.addEventListener('updatefound', ()=>offer(swReg.installing));
      navigator.serviceWorker.addEventListener('controllerchange', ()=>{ if(!updateRequested) return; updateRequested=false; if(!key) location.reload(); else toast('Atualização pronta. Ela entra na próxima abertura.', 4000); });
    } catch(e){ /* sem SW: o app funciona online normalmente */ }
  });
}
function showUpdate(reg){
  const ids=['updateBtn','updateBtnLock'];
  ids.forEach(id=>{ const b=$(id); b.classList.remove('hidden'); b.onclick=()=>{ ids.forEach(x=>$(x).classList.add('hidden')); const w=reg.waiting; if(w){ updateRequested=true; w.postMessage({type:'SKIP_WAITING'}); } }; });
}

// ---------- teclado virtual ----------
// No iOS o teclado não reduz 100dvh; a área visível real vem do visualViewport. O modal acompanha essa área
// para Salvar/Cancelar ficarem sempre acima do teclado.
function syncViewport(){
  const vv=window.visualViewport; if(!vv) return;
  const r=document.documentElement.style;
  r.setProperty('--vvh', vv.height+'px'); r.setProperty('--vvt', vv.offsetTop+'px');
  document.documentElement.classList.toggle('kb', vv.height < window.innerHeight - 120);
}
if(window.visualViewport){ visualViewport.addEventListener('resize', syncViewport); visualViewport.addEventListener('scroll', syncViewport); syncViewport(); }

showLock();
})();
