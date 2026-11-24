'use strict';
/* A30 — Add one unobtrusive navigation cue to the existing host rows.
   A29 remains responsible for real metrics, popovers and all navigation. */
const nc30PreviousReworkTalkers=nc29ReworkTalkers;
nc29ReworkTalkers=function(...args){
  const outcome=nc30PreviousReworkTalkers(...args);
  const list=document.getElementById('dashTalkers');
  if(!list)return outcome;
  for(const row of list.querySelectorAll('.nc29-talker-row')){
    const arrow=document.createElementNS('http://www.w3.org/2000/svg','svg');
    arrow.classList.add('nc30-talker-chevron');
    arrow.setAttribute('aria-hidden','true');
    arrow.setAttribute('focusable','false');
    const icon=document.createElementNS('http://www.w3.org/2000/svg','use');
    icon.setAttribute('href','#i-chevron');arrow.append(icon);row.append(arrow);
  }
  return outcome;
};
/* An Escape dismissal should not immediately re-open a hover tooltip by
   programmatically focusing its trigger. Real keyboard focus is preserved. */
document.addEventListener('keydown',event=>{
  if(event.key!=='Escape'||!nc29ContextInfo.anchor)return;
  nc29CloseInfo();
  event.preventDefault();
  event.stopImmediatePropagation();
},true);
