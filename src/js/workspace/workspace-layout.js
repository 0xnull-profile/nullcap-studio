'use strict';
/* A22 — View-only orchestration. Uses existing forensic workspace state,
   capture operations and report/export actions without mutating evidence. */
function nc22SyncCaseOverview(){
  const root=document.getElementById('view-forensic');if(!root)return;
  const slots=nc40.captures||[];
  const caseName=document.getElementById('nc22CaseName');
  if(caseName){caseName.textContent=nc40.title||'Indagine senza titolo';caseName.title=caseName.textContent;}
  const ready=slots.filter(slot=>slot.ready&&!slot.partial).length;
  const incomplete=slots.filter(slot=>slot.ready&&slot.partial).length;
  const label=document.getElementById('nc22AnalyzedCount');
  if(label){label.textContent=ready+' analizzat'+(ready===1?'a':'e')+(incomplete?' · '+incomplete+' parzial'+(incomplete===1?'e':'i'):'');label.title='Analisi approfondita completata per '+ready+' di '+slots.length+' catture. Le altre possono richiedere l’attivazione.';}
  const active=slots.find(slot=>slot.id===nc40.active);
  const activeLabel=document.getElementById('nc22ActiveCapture');
  if(activeLabel){activeLabel.textContent=active?nc40Label(active):'Nessuna';activeLabel.title=active?nc40Label(active):'Nessuna cattura attiva';}
  const hint=document.getElementById('nc22CaptureHint');
  if(hint)hint.textContent=slots.length?slots.length+' in memoria · clicca per selezionare':'Nessuna cattura importata';
  root.dataset.nc22Tab=nc40.tab;
  nc22UpdateStatus();
}
function nc22UpdateStatus(){
  const container=document.querySelector('#view-forensic .nc22-case-messages');
  if(!container)return;
  const missing=(nc40.expected||[]).some(expected=>!nc40Slot(expected.id));
  const progress=document.getElementById('nc401PortableProgress');
  const progressing=Boolean(progress?.textContent.trim());
  container.dataset.nc22Alert=missing?'true':'false';
  container.classList.toggle('is-visible',missing||progressing);
}
const nc22PreviousRefresh=nc40Refresh;
nc40Refresh=function(...args){const result=nc22PreviousRefresh(...args);nc22SyncCaseOverview();return result;};
const nc22PreviousSetTab=nc40SetTab;
nc40SetTab=function(tab){const result=nc22PreviousSetTab(tab);nc22SyncCaseOverview();return result;};
const nc22PreviousRenderTab=nc40RenderTab;
nc40RenderTab=function(...args){const result=nc22PreviousRenderTab(...args);nc22SyncCaseOverview();return result;};
const nc22PreviousRestoreFields=nc40RestoreFields;
nc40RestoreFields=function(...args){const result=nc22PreviousRestoreFields(...args);nc22SyncCaseOverview();return result;};
const nc22PreviousWireUI=wireUI;
wireUI=function(){
  nc22PreviousWireUI();
  const $=id=>document.getElementById(id);
  const more=$('nc22MoreActions');
  $('nc40CaseTitle').addEventListener('input',nc22SyncCaseOverview);
  for(const id of ['nc40ExportCase','nc40ImportCase'])$(id).addEventListener('click',()=>{more.open=false;});
  document.addEventListener('pointerdown',event=>{if(more.open&&!more.contains(event.target))more.open=false;});
  document.addEventListener('keydown',event=>{if(event.key==='Escape'&&more.open){more.open=false;more.querySelector('summary').focus();}});
  const progress=$('nc401PortableProgress');
  if(progress&&typeof MutationObserver!=='undefined')new MutationObserver(nc22UpdateStatus).observe(progress,{childList:true,subtree:true,characterData:true});
  nc22SyncCaseOverview();
};
