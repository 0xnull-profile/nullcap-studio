'use strict';
/* A31 - One read-only case name in the sidebar and accessible global exports.
   Case name editing still occurs exclusively in Forensic Workspace A23. */
function nc31SyncSidebarCaseName(){
  const label=document.getElementById('nc31SidebarCaseName');
  if(!label)return;
  const value=typeof nc40==='undefined'?'':String(nc40.title??'').trim();
  const display=!value||value==='Indagine senza titolo'?'Senza titolo...':value;
  label.textContent=display;
  label.title=display;
  label.closest('.workspace-title')?.setAttribute('title',display);
}
// All change paths (name input, case JSON, portable ZIP and refresh) share the
// existing nc40 state. These wrappers only refresh the sidebar text.
const nc31OriginalCaseRefresh=nc40Refresh;
nc40Refresh=function(...args){const result=nc31OriginalCaseRefresh(...args);nc31SyncSidebarCaseName();return result;};
const nc31OriginalRestoreFields=nc40RestoreFields;
nc40RestoreFields=function(...args){const result=nc31OriginalRestoreFields(...args);nc31SyncSidebarCaseName();return result;};
const nc31OriginalWireUI=wireUI;
wireUI=function(){
  nc31OriginalWireUI();
  const menu=document.getElementById('nc31MoreActions');
  const trigger=menu?.querySelector('summary');
  document.getElementById('nc40CaseTitle')?.addEventListener('input',nc31SyncSidebarCaseName);
  if(menu&&trigger){
    // The export handlers on their buttons remain untouched.
    menu.querySelectorAll('button').forEach(button=>button.addEventListener('click',()=>{menu.open=false;}));
    document.addEventListener('pointerdown',event=>{
      if(menu.open&&!menu.contains(event.target))menu.open=false;
    });
    document.addEventListener('keydown',event=>{
      if(menu.open&&event.key==='Escape'){
        event.preventDefault();event.stopPropagation();menu.open=false;trigger.focus();
      }
    });
  }
  nc31SyncSidebarCaseName();
};
