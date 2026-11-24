'use strict';
/* NullCap 3.1.2 — small functional additions without a platform restyle. */
const nc312PreviousPacketInspector=renderPacketInspector;
renderPacketInspector=function(){
  nc312PreviousPacketInspector();
  const p=state.selectedPacket;
  if(!p?.hasSensitiveData)return;
  const root=$('packetInspectorContent');
  const warning=document.createElement('div');
  warning.className='nc312-packet-warning';
  warning.setAttribute('role','note');
  warning.innerHTML=ncIcon('alert')+'<span>Il payload di questo frame trasporta credenziali o token HTTP in chiaro. Esamina i byte solo in un contesto autorizzato.</span>';
  root.insertBefore(warning,root.firstChild);
};
const nc312PreviousWireUI=wireUI;
wireUI=function(){
  nc312PreviousWireUI();
  const wrapper=$('graphHelpWrap'),button=$('graphInfoButton'),popover=$('graphInfoPopover');
  let pinned=false;
  const show=visible=>{
    popover.hidden=!visible;
    button.setAttribute('aria-expanded',String(visible));
    wrapper.classList.toggle('is-open',visible);
  };
  wrapper.addEventListener('mouseenter',()=>show(true));
  wrapper.addEventListener('mouseleave',()=>{if(!pinned)show(false);});
  wrapper.addEventListener('focusin',()=>show(true));
  wrapper.addEventListener('focusout',e=>{if(!pinned&&!wrapper.contains(e.relatedTarget))show(false);});
  button.addEventListener('click',e=>{
    e.stopPropagation();
    pinned=!pinned;
    show(pinned);
  });
  document.addEventListener('pointerdown',e=>{if(!wrapper.contains(e.target)){pinned=false;show(false);}});
  document.addEventListener('keydown',e=>{if(e.key==='Escape'&&!popover.hidden){pinned=false;show(false);button.blur();}},true);
};
