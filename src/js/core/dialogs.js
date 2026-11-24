'use strict';
/* A26 shared non-blocking dialogs; every native confirm/prompt in active modules uses these. */
const nc26ModalStack=[];
let nc26DialogResolve=null;
let nc26DialogQueue=Promise.resolve();
function nc26El(id){return document.getElementById(id);}
function nc26CurrentModal(){return nc26ModalStack[nc26ModalStack.length-1]||null;}
function nc26OpenOverlay(id){
  const el=nc26El(id);if(!el)return;
  if(nc26ModalStack.some(s=>s.el===el)){el.querySelector('.nc26-modal-x')?.focus();return;}
  const opener=document.activeElement;
  el.hidden=false;
  nc26ModalStack.push({el,opener});
  document.body.classList.add('nc26-modal-lock');
  const focusable=el.querySelector('.nc26-modal-x, input, button, [tabindex="-1"]');
  requestAnimationFrame(()=>{if(!el.hidden)(focusable||el.querySelector('[role="dialog"]'))?.focus();});
}
function nc26CloseOverlay(id){
  const at=nc26ModalStack.findIndex(s=>s.el.id===id);if(at<0)return;
  const [entry]=nc26ModalStack.splice(at,1);entry.el.hidden=true;
  if(!nc26ModalStack.length)document.body.classList.remove('nc26-modal-lock');
  const next=nc26CurrentModal();
  if(next){const target=entry.opener?.isConnected&&next.el.contains(entry.opener)?entry.opener:next.el.querySelector('button,[tabindex="-1"]');target?.focus();}
  else if(entry.opener?.isConnected)entry.opener.focus({preventScroll:true});
}
function nc26ClosePreview(){nc26CloseOverlay('nc24DossierPreview');}
function nc26CloseReport(){nc26CloseOverlay('nc26ReportModal');}
function nc26GlobalKeydown(event){
  const current=nc26CurrentModal();if(!current)return;
  if(event.key==='Escape'){
    event.preventDefault();event.stopImmediatePropagation();
    if(current.el.id==='nc26SystemModal')nc26DialogRespond(false);
    else nc26CloseOverlay(current.el.id);
    return;
  }
  if(event.key!=='Tab')return;
  const nodes=[...current.el.querySelectorAll('button:not([disabled]),input:not([disabled]),textarea:not([disabled]),select:not([disabled]),[tabindex="0"]')]
    .filter(n=>!n.hidden&&n.getAttribute('aria-hidden')!=='true'&&n.getClientRects().length);
  if(!nodes.length){event.preventDefault();return;}
  const first=nodes[0],last=nodes[nodes.length-1],active=document.activeElement;
  if(event.shiftKey&&(active===first||!current.el.contains(active))){event.preventDefault();last.focus();}
  else if(!event.shiftKey&&(active===last||!current.el.contains(active))){event.preventDefault();first.focus();}
  // Do not trigger the background notebook's focus trap.
  event.stopImmediatePropagation();
}
window.addEventListener('keydown',nc26GlobalKeydown,true);
function nc26DialogRespond(ok){
  const resolve=nc26DialogResolve;if(!resolve)return;
  nc26DialogResolve=null;
  const kind=nc26El('nc26SystemForm').dataset.mode;
  const value=ok?(kind==='prompt'?nc26El('nc26SystemInput').value:true):(kind==='prompt'?null:false);
  nc26CloseOverlay('nc26SystemModal');resolve(value);
}
function nc26RequestDialog(mode,message,defaultValue='',options={}){
  const ask=()=>new Promise(resolve=>{
    const form=nc26El('nc26SystemForm');if(!form){resolve(mode==='prompt'?null:false);return;}
    form.dataset.mode=mode;
    const dangerous=/rimuov|elimin|sostituir|cancell/i.test(String(message));
    const sensitive=/password|token|credenzial|riservat|sensibil|PCAP|ZIP|sorgente/i.test(String(message));
    form.dataset.kind=dangerous?'danger':sensitive?'warning':'info';
    nc26El('nc26SystemIcon').querySelector('use').setAttribute('href','#'+(dangerous?'i-alert':sensitive?'i-shield':'i-info'));
    const title=options.title||(mode==='prompt'?'Nuovo segnalibro':mode==='alert'?'Informazione':dangerous?'Conferma modifica':sensitive?'Conferma e verifica dati':'Conferma operazione');
    nc26El('nc26SystemTitle').textContent=title;
    nc26El('nc26SystemText').textContent=String(message||'');
    const inputWrap=nc26El('nc26SystemInputWrap'),input=nc26El('nc26SystemInput');
    inputWrap.hidden=mode!=='prompt';input.value=String(defaultValue??'');
    nc26El('nc26SystemCancel').hidden=mode==='alert';
    nc26El('nc26SystemSubmit').textContent=options.confirmLabel||(mode==='prompt'?'Salva segnalibro':mode==='alert'?'Chiudi':dangerous?'Conferma rimozione':'Conferma');
    nc26DialogResolve=resolve;nc26OpenOverlay('nc26SystemModal');
    if(mode==='prompt')requestAnimationFrame(()=>{input.focus();input.select();});
  });
  const next=nc26DialogQueue.then(ask,ask);
  nc26DialogQueue=next.then(()=>undefined,()=>undefined);
  return next;
}
function nc26Confirm(message,options){return nc26RequestDialog('confirm',message,'',options);}
function nc26Prompt(message,fallback){return nc26RequestDialog('prompt',message,fallback);}
function nc26Alert(message,options){return nc26RequestDialog('alert',message,'',options);}
function nc26WireSystemModal(){
  const form=nc26El('nc26SystemForm');
  form.addEventListener('submit',e=>{e.preventDefault();nc26DialogRespond(true);});
  nc26El('nc26SystemX').onclick=()=>nc26DialogRespond(false);
  nc26El('nc26SystemCancel').onclick=()=>nc26DialogRespond(false);
}
