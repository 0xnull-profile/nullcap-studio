'use strict';
/* NullCap Studio 4.0.1 / Explorer UX A04.
   Interface refinements: unified focus treatment, conditional timeline window,
   icon-only host actions, contextual help, and a native-free bookmark workflow.
   Packet data, capture bytes, and existing bookmark storage remain unchanged. */

let ncA04MarkMenuOpen=false;
let ncA04BookmarkDialogOpen=false;
let ncA04PreviousBookmarkFocus=null;

function ncA04SyncWindowVisibility(){
  const label=document.querySelector('#view-explorer .ncux-window-selector');
  if(!label)return;
  label.classList.toggle('ncA04-window-concealed',state.mode!=='window');
}
const ncA04PrevUpdateSnapshot=updateSnapshot;
updateSnapshot=function(...args){
  const result=ncA04PrevUpdateSnapshot(...args);
  ncA04SyncWindowVisibility();
  return result;
};

/* The v3.2 host pin renderer writes a textual label on every host change.
   Keep its actual toggle behavior and selected-host state, but use icon-only UI. */
const ncA04PrevUpdatePin=nc32UpdatePin;
nc32UpdatePin=function(){
  ncA04PrevUpdatePin();
  const el=$('nc32PinHost');
  if(!el)return;
  const pin=!!state.aliasSelectedIP&&state.nc32Pinned.has(state.aliasSelectedIP);
  const label=pin?'Rimuovi host dai fissati':'Fissa host sulla mappa';
  el.innerHTML='<svg aria-hidden="true"><use href="#i-'+(pin?'pin-off':'pin')+'"/></svg>';
  el.setAttribute('aria-label',label);
  el.title=label;
  el.classList.toggle('is-pinned',pin);
};

function ncA04SetAliasHelp(open){
  const wrap=$('ncA04AliasInfoWrap'),button=$('ncA04AliasInfoButton');
  if(!wrap||!button)return;
  wrap.classList.toggle('is-open',!!open);
  button.setAttribute('aria-expanded',String(!!open));
}

/* The hidden native select is still the single source of truth for all v3.2
   bookmark operations. A styled, keyboard-accessible picker mirrors its state. */
const ncA04PrevRenderMarkOptions=nc32RenderMarkOptions;
nc32RenderMarkOptions=function(){
  ncA04PrevRenderMarkOptions();
  ncA04RenderBookmarkOptions();
};
function ncA04RenderBookmarkOptions(){
  const native=$('nc32MarkSelect'),toggle=$('ncA04MarkToggle');
  const menu=$('ncA04MarkMenu'),value=$('ncA04MarkValue');
  if(!native||!toggle||!menu||!value)return;
  const marks=nc32Marks(),selected=native.value;
  const current=selected!==''?marks[Number(selected)]:null;
  value.textContent=current?current.name:'Segnalibri ('+marks.length+')';
  toggle.title=current?current.name+' · '+formatTime(current.time,true):'Apri i segnalibri della timeline';
  toggle.setAttribute('aria-label',current?'Segnalibro selezionato: '+current.name:'Segnalibri ('+marks.length+')');
  toggle.classList.toggle('has-selection',!!current);
  menu.innerHTML='<div class="ncux-proto-menu-caption">SEGNALIBRI DELLA CATTURA <span class="ncA04-mark-total">'+marks.length+'</span></div>'+(
    marks.length?marks.map((mark,index)=>
      '<button type="button" class="ncA04-mark-option" role="option" tabindex="-1" data-ncA04-mark="'+index+'" aria-selected="'+(selected===String(index))+'">'+
      '<span class="ncA04-mark-option-icon"><svg aria-hidden="true"><use href="#i-bookmark"/></svg></span>'+ 
      '<span class="ncA04-mark-option-content"><strong>'+escapeHtml(mark.name)+'</strong><small>'+formatTime(mark.time,true)+'</small></span>'+ 
      '<span class="ncA04-mark-check" aria-hidden="true"><svg><use href="#i-check"/></svg></span></button>'
    ).join(''):'<div class="ncA04-mark-empty">Nessun segnalibro creato.<small>Usa “Segna” per annotare un istante del replay.</small></div>'
  );
  if(ncA04MarkMenuOpen)ncA04PositionMarkMenu();
}
function ncA04PositionMarkMenu(){
  const toggle=$('ncA04MarkToggle'),menu=$('ncA04MarkMenu');
  if(!toggle||!menu)return;
  const rect=toggle.getBoundingClientRect();
  const width=Math.min(318,Math.max(245,window.innerWidth-22));
  const height=Math.min(menu.scrollHeight||300,330);
  menu.style.position='fixed';
  menu.style.width=width+'px';
  menu.style.left=Math.max(8,Math.min(rect.left,window.innerWidth-width-8))+'px';
  menu.style.top=(window.innerHeight-rect.bottom>=height+12?rect.bottom+7:Math.max(8,rect.top-height-7))+'px';
}
function ncA04SetMarkMenuOpen(open,focusOption=false){
  const menu=$('ncA04MarkMenu'),toggle=$('ncA04MarkToggle');
  if(!menu||!toggle)return;
  ncA04MarkMenuOpen=!!open;
  menu.classList.toggle('hidden',!open);
  toggle.setAttribute('aria-expanded',String(!!open));
  if(open){
    ncA04RenderBookmarkOptions();
    ncA04PositionMarkMenu();
    if(focusOption){
      const selected=menu.querySelector('[aria-selected="true"]');
      (selected||menu.querySelector('[role="option"]'))?.focus();
    }
  }
}
function ncA04SelectBookmark(index){
  const native=$('nc32MarkSelect');
  if(!native||!nc32Marks()[index])return;
  native.value=String(index);
  native.dispatchEvent(new Event('change',{bubbles:true}));
  ncA04SetMarkMenuOpen(false);
  ncA04RenderBookmarkOptions();
  $('ncA04MarkToggle').focus();
}
function ncA04BookmarkMenuKey(e){
  const menu=$('ncA04MarkMenu');
  if(e.key==='Escape'){
    e.preventDefault();e.stopPropagation();ncA04SetMarkMenuOpen(false);$('ncA04MarkToggle').focus();return;
  }
  const options=[...menu.querySelectorAll('[role="option"]')];
  if(!options.length)return;
  const index=options.indexOf(document.activeElement);
  if(['ArrowDown','ArrowUp','Home','End'].includes(e.key)){
    e.preventDefault();
    const next=e.key==='Home'?0:e.key==='End'?options.length-1:e.key==='ArrowDown'?Math.min(index+1,options.length-1):Math.max(index-1,0);
    options[next]?.focus();
  }else if((e.key==='Enter'||e.key===' ')&&index>=0){
    e.preventDefault();ncA04SelectBookmark(Number(options[index].dataset.nca04Mark));
  }
}

function ncA04OpenBookmarkDialog(){
  if(!state.packets.length||!Number.isFinite(state.duration)||state.duration<=0){
    notify('Timeline priva di eventi datati','Non è possibile creare un segnalibro.',true);return;
  }
  if(nc32Marks().length>=100){
    notify('Limite segnalibri raggiunto','Massimo 100 per indagine.',true);return;
  }
  ncA04SetMarkMenuOpen(false);
  ncA04BookmarkDialogOpen=true;
  ncA04PreviousBookmarkFocus=document.activeElement;
  const modal=$('ncA04BookmarkDialog');
  $('ncA04BookmarkTime').textContent=formatTime(state.playhead,true);
  $('ncA04BookmarkName').value='Evento '+formatTime(state.playhead,true);
  modal.hidden=false;
  document.querySelector('.app-shell')?.setAttribute('inert','');
  requestAnimationFrame(()=>{$('ncA04BookmarkName').focus();$('ncA04BookmarkName').select();});
}
function ncA04CloseBookmarkDialog(){
  if(!ncA04BookmarkDialogOpen)return;
  ncA04BookmarkDialogOpen=false;
  $('ncA04BookmarkDialog').hidden=true;
  document.querySelector('.app-shell')?.removeAttribute('inert');
  const target=ncA04PreviousBookmarkFocus?.isConnected?ncA04PreviousBookmarkFocus:$('nc32MarkAdd');
  target?.focus({preventScroll:true});
}
function ncA04SaveBookmark(e){
  e.preventDefault();
  const fallback='Evento '+formatTime(state.playhead,true);
  const value=$('ncA04BookmarkName').value.trim().slice(0,70)||fallback;
  if(!state.investigation||nc32Marks().length>=100){ncA04CloseBookmarkDialog();return;}
  state.investigation.timelineMarks.push({time:+state.playhead.toFixed(4),name:value});
  nc31SaveCase();
  nc32RenderMarkOptions();
  drawTimeline();
  ncA04CloseBookmarkDialog();
  notify('Segnalibro creato',value+' · '+formatTime(state.playhead,true));
}
function ncA04TrapBookmarkDialog(e){
  if(!ncA04BookmarkDialogOpen)return;
  if(e.key==='Escape'){
    e.preventDefault();e.stopImmediatePropagation();ncA04CloseBookmarkDialog();return;
  }
  if(e.key!=='Tab')return;
  const items=[...$('ncA04BookmarkDialog').querySelectorAll('button:not(:disabled),input:not(:disabled)')];
  const first=items[0],last=items[items.length-1];
  if(e.shiftKey&&document.activeElement===first){e.preventDefault();last.focus();}
  else if(!e.shiftKey&&document.activeElement===last){e.preventDefault();first.focus();}
}

function ncA04BindUI(){
  ncA04SyncWindowVisibility();
  document.querySelectorAll('#view-explorer [data-mode]').forEach(button=>button.addEventListener('click',ncA04SyncWindowVisibility));
  nc32UpdatePin();
  const info=$('ncA04AliasInfoWrap');
  $('ncA04AliasInfoButton').onclick=()=>ncA04SetAliasHelp(!info.classList.contains('is-open'));
  info.addEventListener('keydown',e=>{
    if(e.key==='Escape'){
      e.stopPropagation();ncA04SetAliasHelp(false);$('ncA04AliasInfoButton').focus();
    }
  });
  $('nc32MarkAdd').onclick=ncA04OpenBookmarkDialog;
  $('ncA04BookmarkForm').onsubmit=ncA04SaveBookmark;
  $('ncA04BookmarkClose').onclick=ncA04CloseBookmarkDialog;
  $('ncA04BookmarkCancel').onclick=ncA04CloseBookmarkDialog;
  $('ncA04BookmarkDialog').addEventListener('click',e=>{
    if(e.target.matches('[data-ncA04-cancel]'))ncA04CloseBookmarkDialog();
  });
  document.addEventListener('keydown',ncA04TrapBookmarkDialog,true);
  const menu=$('ncA04MarkMenu');
  document.body.appendChild(menu); // Avoid timeline pane clipping and transformed ancestors.
  $('ncA04MarkToggle').onclick=()=>ncA04SetMarkMenuOpen(!ncA04MarkMenuOpen,true);
  $('ncA04MarkToggle').onkeydown=e=>{
    if(['ArrowDown','ArrowUp'].includes(e.key)){
      e.preventDefault();ncA04SetMarkMenuOpen(true,true);
    }else if(e.key==='Escape')ncA04SetMarkMenuOpen(false);
  };
  menu.addEventListener('keydown',ncA04BookmarkMenuKey);
  menu.addEventListener('click',e=>{
    const item=e.target.closest('[data-ncA04-mark]');
    if(item)ncA04SelectBookmark(Number(item.dataset.nca04Mark));
  });
  $('nc32MarkRemove').addEventListener('click',()=>queueMicrotask(()=>{
    ncA04SetMarkMenuOpen(false);ncA04RenderBookmarkOptions();
  }));
  document.addEventListener('pointerdown',e=>{
    if(ncA04MarkMenuOpen&&!$('ncA04MarkPicker').contains(e.target)&&!menu.contains(e.target))ncA04SetMarkMenuOpen(false);
    if(info.classList.contains('is-open')&&!info.contains(e.target))ncA04SetAliasHelp(false);
  });
  window.addEventListener('resize',()=>{if(ncA04MarkMenuOpen)ncA04PositionMarkMenu();});
  document.addEventListener('scroll',()=>{if(ncA04MarkMenuOpen)ncA04PositionMarkMenu();},true);
  ncA04RenderBookmarkOptions();
}
const ncA04PrevWireUI=wireUI;
wireUI=function(){ncA04PrevWireUI();ncA04BindUI();};
