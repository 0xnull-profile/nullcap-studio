'use strict';
/* A23 — One editable case-details panel, preserving v40's original input handlers,
   workspace persistence, JSON import/export and all evidence data. */
function nc23SyncAnalyst(){
  const label=document.getElementById('nc23CaseAnalyst');
  if(!label)return;
  const value=(nc40.analyst||'').trim();
  label.textContent=value?' · Analista: '+value:'';
  label.hidden=!value;
}
const nc23PreviousRefresh=nc40Refresh;
nc40Refresh=function(...args){const result=nc23PreviousRefresh(...args);nc23SyncAnalyst();return result;};
const nc23PreviousRestoreFields=nc40RestoreFields;
nc40RestoreFields=function(...args){const result=nc23PreviousRestoreFields(...args);nc23SyncAnalyst();return result;};
const nc23PreviousWireUI=wireUI;
wireUI=function(){
  nc23PreviousWireUI();
  const trigger=document.getElementById('nc23CaseDetailsToggle');
  const panel=document.getElementById('nc23CaseDetails');
  const close=document.getElementById('nc23CaseDetailsClose');
  const title=document.getElementById('nc40CaseTitle');
  const analyst=document.getElementById('nc40Analyst');
  if(!trigger||!panel||!close||!title||!analyst)return;
  function toggleDetails(open,restoreFocus=false){
    panel.hidden=!open;
    trigger.setAttribute('aria-expanded',String(open));
    if(open)title.focus();else if(restoreFocus)trigger.focus();
  }
  trigger.addEventListener('click',()=>toggleDetails(panel.hidden,!panel.hidden));
  close.addEventListener('click',()=>toggleDetails(false,true));
  document.addEventListener('keydown',event=>{
    if(event.key==='Escape'&&!panel.hidden){event.preventDefault();toggleDetails(false,true);}
  });
  analyst.addEventListener('input',nc23SyncAnalyst);
  nc23SyncAnalyst();
};
