 'use strict';
/* A15 · Conversation navigation and shared iconography, layered over A14. */
const nc15SVG = name => `<svg aria-hidden="true" focusable="false"><use href="#i-${name}"/></svg>`;
const nc15Visible = () => (nc13UI.visible || []).slice(0, 350);
function nc15MoveConversation(delta){
  const visible=nc15Visible();if(!visible.length)return;
  const at=visible.findIndex(f=>f.id===state.selectedFlow);
  const dest=at<0?0:Math.min(Math.max(0,at+delta),visible.length-1);
  if(dest===at)return;
  state.selectedFlow=visible[dest].id;
  renderFlows();renderFlowInspector();
  const host=document.getElementById('flowsList');
  const row=[...host.querySelectorAll('[data-flow]')].find(n=>n.dataset.flow===state.selectedFlow);
  if(row){
    const container=host.getBoundingClientRect(),rect=row.getBoundingClientRect();
    if(rect.top<container.top+4)host.scrollTop+=rect.top-container.top-4;
    else if(rect.bottom>container.bottom-4)host.scrollTop+=rect.bottom-container.bottom+4;
  }
}
const nc15PreviousRender=renderFlowInspector;
renderFlowInspector=function(){
  nc15PreviousRender();
  const container=document.querySelector('#flowInspectorContent .nc14-sticky-actions');
  if(!container)return;
  const current=nc15Visible();
  const at=current.findIndex(f=>f.id===state.selectedFlow);
  const createNav=(id,label,icon,delta,disabled)=>{
    const button=document.createElement('button');
    button.type='button';button.id=id;button.className='nc15-action-btn';
    button.setAttribute('aria-label',label);button.setAttribute('data-tip',label);
    button.disabled=disabled;button.innerHTML=nc15SVG(icon);
    button.addEventListener('click',()=>nc15MoveConversation(delta));return button;
  };
  const nav=document.createElement('div');nav.className='nc15-action-group nc15-nav';
  nav.append(createNav('nc15PrevFlow','Conversazione precedente','arrow-left',-1,at<=0),
             createNav('nc15NextFlow','Conversazione successiva','arrow-right',1,at<0||at>=current.length-1));
  const tools=document.createElement('div');tools.className='nc15-action-group nc15-tools';
  const p=container.querySelector('#flowToPackets');
  const g=container.querySelector('#flowToGraph');
  const follow=container.querySelector('#nc13FollowTCP');
  for(const button of [p,g,follow]){
    if(!button)continue;
    button.classList.add('nc15-action-btn');tools.append(button);
  }
  // Packet inspector's "Segui TCP" icon and every "Mostra nel grafo" button
  // use the exact same shared SVG symbol.
  if(g)g.innerHTML=nc15SVG('graph-star');
  if(follow)follow.innerHTML=nc15SVG('flows');
  container.classList.add('nc15-actions');container.replaceChildren(nav,tools);
};
