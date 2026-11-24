'use strict';
/* A21: Artifact Inspector — observed cleartext values first and a quiet,
 * accessible evidence-quality popover. All observation values come from the
 * already parsed, volatile HTTP event: never inferred, verified or exported.
 * Do not change TCP reconstruction, evidence bytes or navigation handlers.
 */
const nc21QualityUI={anchor:null,popover:null,open:false,pinned:false,leaveTimer:null};
function nc21CancelLeave(){
  if(nc21QualityUI.leaveTimer!==null){clearTimeout(nc21QualityUI.leaveTimer);nc21QualityUI.leaveTimer=null;}
}
function nc21CloseQualityInfo(){
  nc21CancelLeave();
  if(nc21QualityUI.anchor)nc21QualityUI.anchor.setAttribute('aria-expanded','false');
  if(nc21QualityUI.popover)nc21QualityUI.popover.hidden=true;
  nc21QualityUI.open=false;nc21QualityUI.pinned=false;nc21QualityUI.anchor=null;
}
function nc21QualityInfoPosition(){
  const {anchor,popover,open}=nc21QualityUI;
  if(!open||!anchor?.isConnected||!popover)return;
  const r=anchor.getBoundingClientRect(),width=Math.min(324,innerWidth-20);
  popover.style.width=width+'px';
  popover.style.maxHeight=Math.max(116,Math.min(306,innerHeight-32))+'px';
  const pw=popover.offsetWidth,ph=popover.offsetHeight;
  const x=Math.max(10,Math.min(innerWidth-pw-10,r.right-pw));
  const below=innerHeight-r.bottom-10,above=r.top-10;
  const belowPreferred=below>=Math.min(210,ph)||below>=above;
  const y=belowPreferred?r.bottom+5:r.top-ph-5;
  popover.style.left=x+'px';
  popover.style.top=Math.max(10,Math.min(innerHeight-ph-10,y))+'px';
}
function nc21QualityInfoEnsure(){
  if(nc21QualityUI.popover)return nc21QualityUI.popover;
  const popover=document.createElement('div');
  popover.id='nc21QualityPopover';popover.className='nc21-quality-popover';
  popover.setAttribute('role','tooltip');popover.hidden=true;
  popover.addEventListener('pointerenter',nc21CancelLeave);
  popover.addEventListener('pointerleave',nc21ScheduleQualityLeave);
  document.body.append(popover);nc21QualityUI.popover=popover;
  document.addEventListener('pointerdown',e=>{
    if(!nc21QualityUI.open)return;
    if(nc21QualityUI.anchor?.contains(e.target)||popover.contains(e.target))return;
    nc21CloseQualityInfo();
  },true);
  document.addEventListener('keydown',e=>{
    if(e.key==='Escape'&&nc21QualityUI.open){
      e.preventDefault();e.stopImmediatePropagation();
      const back=nc21QualityUI.anchor;nc21CloseQualityInfo();back?.focus();
    }
  },true);
  window.addEventListener('resize',nc21QualityInfoPosition);
  document.getElementById('lootDetail')?.addEventListener('scroll',nc21QualityInfoPosition,{passive:true});
  return popover;
}
function nc21QualityInfoOpen(button,pinned=false){
  nc21CancelLeave();
  const popover=nc21QualityInfoEnsure();
  if(nc21QualityUI.anchor&&nc21QualityUI.anchor!==button)nc21CloseQualityInfo();
  nc21QualityUI.anchor=button;nc21QualityUI.open=true;
  nc21QualityUI.pinned=!!(pinned||nc21QualityUI.pinned);
  popover.hidden=false;
  button.setAttribute('aria-expanded','true');
  nc21QualityInfoPosition();
}
function nc21ScheduleQualityLeave(e){
  if(!nc21QualityUI.open||nc21QualityUI.pinned)return;
  const next=e?.relatedTarget;
  if(next&&(nc21QualityUI.anchor?.contains(next)||nc21QualityUI.popover?.contains(next)))return;
  nc21CancelLeave();
  nc21QualityUI.leaveTimer=setTimeout(()=>{
    if(!nc21QualityUI.pinned)nc21CloseQualityInfo();
  },140);
}
function nc21QualityInfoAttach(button,originalNodes){
  const popover=nc21QualityInfoEnsure();
  popover.replaceChildren();
  const heading=document.createElement('strong');heading.className='nc21-popover-title';
  heading.textContent='Dettagli e avvertenze';popover.append(heading);
  for(const node of originalNodes)if(node)popover.append(node.cloneNode(true));
  button.addEventListener('pointerenter',()=>nc21QualityInfoOpen(button,false));
  button.addEventListener('pointerleave',nc21ScheduleQualityLeave);
  button.addEventListener('click',e=>{
    e.stopPropagation();
    // A click while open through hover pins the explanation, like other NullCap info controls.
    if(nc21QualityUI.open&&nc21QualityUI.anchor===button){
      if(nc21QualityUI.pinned)nc21CloseQualityInfo();
      else nc21QualityInfoOpen(button,true);
    }else nc21QualityInfoOpen(button,true);
  });
}
function nc21QualitySection(quality,asset){
  const source=nc16Quality(asset);
  const explanation=quality.querySelector('.nc16-proof');
  const warning=quality.querySelector('.nc312-secret-warning');
  const secondary=quality.querySelector('.nc313-secondary-note');
  const title=document.createElement('h4');title.className='nc21-quality-title';
  title.textContent='Qualità dell’evidenza';
  const info=document.createElement('button');info.type='button';
  info.className='nc21-quality-info';info.setAttribute('aria-label','Dettagli e avvertenze sulla qualità dell’evidenza');
  info.setAttribute('aria-controls','nc21QualityPopover');info.setAttribute('aria-expanded','false');
  info.innerHTML=ncIcon('info');
  const header=document.createElement('div');header.className='nc21-quality-head';header.append(title,info);
  const status=document.createElement('div');status.className='nc21-quality-status nc21-quality-'+source;
  const mark=document.createElement('span');mark.className='nc21-quality-mark';
  mark.innerHTML=ncIcon(source==='complete'?'check-circle':'alert');
  const stateText=document.createElement('strong');
  stateText.textContent=source==='ambiguous'?'Sovrapposizioni ambigue nella sorgente':
    source==='partial'?'Ricostruzione parziale o lacunosa':'Nessuna lacuna nei byte estratti';
  status.append(mark,stateText);
  quality.classList.add('nc21-quality');
  quality.replaceChildren(header,status);
  nc21QualityInfoAttach(info,[explanation,warning,secondary]);
  return source;
}
function nc21FieldKind(item){
  const key=String(item.field||'').toLowerCase();
  if(/(?:password|passwd|pwd|passcode|passphrase)/.test(key))return 'password';
  if(/(?:token|jwt|secret|session|api.?key|auth.?key|access.?key|bearer|authorization)/.test(key)||item.kind==='token')return 'token';
  return item.identity?'identity':'other';
}
function nc21FieldLabel(item){
  const key=String(item.field||'').toLowerCase();
  if(item.identity){
    if(/(?:e.?mail)/.test(key))return 'Email';
    if(/(?:username|user_name|user-name|\blogin\b)/.test(key))return 'Username';
    return 'Identificativo utente';
  }
  const kind=nc21FieldKind(item);
  if(kind==='password')return 'Password';
  if(kind==='token'){
    if(/(?:api.?key|apikey)/.test(key))return 'Chiave API';
    if(item.where==='Authorization Bearer')return 'Token Bearer';
    if(/session/.test(key)||item.where.includes('Set-Cookie'))return 'Token di sessione';
    return 'Token / chiave';
  }
  return item.field||'Valore sensibile';
}
function nc21ObservedValues(asset){
  // v312-auth.js already detected the fields; no attempt to decrypt or deduce secrets.
  const event=(state.httpEvents||[]).find(item=>item.assetId===asset.id);
  const items=[];const seen=new Set();
  // Include tokens actually emitted by the correlated HTTP response. The
  // direction label is essential: a received token is not proof of acceptance.
  for(const [values,identity,response] of [
    [event?.authIdentities,true,false],
    [event?.authHits,false,false],
    [event?.response?.authHits,false,true]
  ]){
    for(const hit of Array.isArray(values)?values:[]){
      if(hit?.value===null||hit?.value===undefined)continue;
      const value=String(hit.value),field=String(hit.field||''),
        where=(response?'Risposta HTTP · ':'')+String(hit.where||'');
      if(!value)continue;
      const key=[field,where,value,identity?'I':'S'].join('\0');
      if(seen.has(key))continue;seen.add(key);
      items.push({value,field,where,kind:hit.kind||'',identity});
    }
  }
  const rank=item=>item.identity?0:nc21FieldKind(item)==='password'?1:nc21FieldKind(item)==='token'?2:3;
  return items.sort((a,b)=>rank(a)-rank(b));
}
function nc21ObservedPanel(asset){
  if(!asset.authFinding)return null;
  const observations=nc21ObservedValues(asset);
  if(!observations.length)return null; // No invented or conjectural values.
  const section=document.createElement('section');section.className='nc21-observed';
  const header=document.createElement('div');header.className='nc21-observed-head';
  const title=document.createElement('h4');title.textContent='Dati osservati in chiaro';
  const tag=document.createElement('span');tag.className='nc21-observed-tag';tag.textContent='DATI SENSIBILI';
  header.append(title,tag);
  const note=document.createElement('p');note.className='nc21-observed-subtitle';
  note.textContent='Valori presenti nel traffico catturato, non credenziali verificate.';
  const body=document.createElement('div');body.className='nc21-observed-list';
  for(const item of observations){
    const field=document.createElement('div');field.className='nc21-observed-field';
    const label=document.createElement('div');label.className='nc21-observed-label';
    label.textContent=nc21FieldLabel(item);
    const value=document.createElement('div');value.className='nc21-observed-value';
    value.textContent=item.value; // textContent prevents execution of recovered payload text.
    const context=document.createElement('div');context.className='nc21-observed-context';
    context.textContent=[item.where,item.field].filter(Boolean).join(' · ');
    field.append(label,value,context);body.append(field);
  }
  section.append(header,note,body);
  return section;
}
function nc21EnhanceInspector(){
  nc21CloseQualityInfo();
  const host=document.getElementById('lootDetail');
  const asset=(state.loot||[]).find(a=>a.id===state.selectedLoot);
  if(!host||!asset||!host.classList.contains('nc20-content-first'))return;
  const identity=host.querySelector('.nc20-identity');
  const actions=host.querySelector('.nc20-actions');
  const quality=host.querySelector('.nc20-quality');
  const preview=host.querySelector('.nc20-preview');
  const provenance=host.querySelector('.nc20-provenance');
  const technical=host.querySelector('.nc20-technical');
  if(!identity||!actions||!quality||!preview||!provenance||!technical)return;
  const sourceQuality=nc21QualitySection(quality,asset);
  const observed=nc21ObservedPanel(asset);
  // Evidence detail becomes a secondary disclosure when observed secrets already
  // form the immediate content. Keep #lootPreview and its bytes/text unchanged.
  if(observed){
    const heading=preview.querySelector('.nc19-section-heading');
    const previewBody=preview.querySelector('#lootPreview');
    if(heading&&previewBody){
      const disclosure=document.createElement('details');disclosure.className='nc21-observation-trace';
      const toggle=document.createElement('summary');
      toggle.innerHTML=ncIcon('file-text');
      toggle.append(document.createTextNode('Traccia testuale completa'));
      const caret=document.createElement('span');caret.className='nc21-trace-caret';caret.innerHTML=ncIcon('chevrondown');toggle.append(caret);
      disclosure.append(toggle,previewBody);
      preview.replaceChildren(disclosure);
    }
  }
  // A20's content-first order remains. Material reassembly risks precede the
  // preview; the warning text itself is available via the information button.
  const content=[identity,actions];
  if(observed)content.push(observed);
  if(sourceQuality!=='complete')content.push(quality);
  content.push(preview,provenance);
  if(sourceQuality==='complete')content.push(quality);
  content.push(technical);
  host.replaceChildren(...content);
  host.classList.add('nc21-inspector');
  host.scrollTop=0;
}
const nc21PriorRenderLootDetail=ncRenderLootDetail;
ncRenderLootDetail=function(){nc21PriorRenderLootDetail();nc21EnhanceInspector();};
