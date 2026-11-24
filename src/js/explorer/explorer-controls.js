'use strict';
/* Explorer UX A05. UI adapters for the existing v3.2 timeline model.
   Native selects remain as hidden state adapters, so data and replay code do
   not need to be duplicated or changed. */

const ncA05Pickers={
  metric:{native:'nc32TimelineMetric',toggle:'ncA05MetricToggle',value:'ncA05MetricValue',menu:'ncA05MetricMenu',name:'Metrica'},
  speed:{native:'speedSelect',toggle:'ncA05SpeedToggle',value:'ncA05SpeedValue',menu:'ncA05SpeedMenu',name:'Velocit\u00e0'},
  window:{native:'windowSeconds',toggle:'ncA06WindowToggle',value:'ncA06WindowValue',menu:'ncA06WindowMenu',name:'Ultimi'}
};
let ncA05OpenPicker=null;
let ncA05ConfirmingMark=null;
const ncA05RenderedValues=new Map();

function ncA05SyncPicker(kind,force=false){
  const c=ncA05Pickers[kind];
  const source=$(c.native),button=$(c.toggle),menu=$(c.menu),label=$(c.value);
  if(!source||!button||!menu||!label)return;
  const selected=source.selectedOptions[0];
  const value=source.value;
  if(!force&&ncA05RenderedValues.get(kind)===value)return;
  ncA05RenderedValues.set(kind,value);
  const textValue=selected?.textContent?.trim()||value;
  label.textContent=textValue;
  button.setAttribute('aria-label',c.name+': '+textValue);
  menu.innerHTML='<div class="ncA05-menu-caption">'+(kind==='metric'?'VISUALIZZA VALORI':kind==='speed'?'VELOCIT\u00c0 DEL REPLAY':'FINESTRA TEMPORALE')+'</div>'+
    [...source.options].map(option=>
      '<button type="button" role="option" tabindex="-1" class="ncA05-select-option" data-nca05-option="'+escapeHtml(option.value)+'" aria-selected="'+(option.value===value)+'">'+
      '<span>'+escapeHtml(option.textContent.trim())+'</span><svg aria-hidden="true"><use href="#i-check"/></svg></button>'
    ).join('');
  if(ncA05OpenPicker===kind)ncA05PositionPicker(kind);
}
function ncA05PositionPicker(kind){
  const c=ncA05Pickers[kind];
  const button=$(c.toggle),menu=$(c.menu);
  if(!button||!menu)return;
  const rect=button.getBoundingClientRect();
  const width=Math.min(Math.max(kind==='speed'?168:160,Math.round(rect.width)),window.innerWidth-16);
  menu.style.width=width+'px';
  menu.style.left=Math.max(8,Math.min(rect.left,window.innerWidth-width-8))+'px';
  const wantedHeight=Math.min(menu.scrollHeight||270,340);
  const belowSpace=Math.max(0,window.innerHeight-rect.bottom-12);
  const aboveSpace=Math.max(0,rect.top-12);
  const placeBelow=belowSpace>=wantedHeight||belowSpace>=aboveSpace;
  const available=placeBelow?belowSpace:aboveSpace;
  const shownHeight=Math.min(wantedHeight,Math.max(40,available));
  menu.style.maxHeight=shownHeight+'px';
  menu.style.top=placeBelow?(rect.bottom+7)+'px':Math.max(8,rect.top-shownHeight-7)+'px';
}
function ncA05SetPickerOpen(kind,open,focusOption=false){
  for(const [name,c] of Object.entries(ncA05Pickers)){
    const active=name===kind&&!!open;
    const panel=$(c.menu),toggle=$(c.toggle);
    panel.classList.toggle('hidden',!active);
    toggle.setAttribute('aria-expanded',String(active));
  }
  ncA05OpenPicker=open?kind:null;
  if(open){
    if(ncA04MarkMenuOpen)ncA04SetMarkMenuOpen(false);
    if(ncuxProtocolIsOpen)ncuxSetProtocolOpen(false);
    ncA05SyncPicker(kind,true);
    ncA05PositionPicker(kind);
    if(focusOption){
      const panel=$(ncA05Pickers[kind].menu);
      (panel.querySelector('[aria-selected="true"]')||panel.querySelector('[role="option"]'))?.focus();
    }
  }
}
function ncA05ClosePickers(){
  if(ncA05OpenPicker)ncA05SetPickerOpen(ncA05OpenPicker,false);
}
function ncA05ChooseValue(kind,value){
  const c=ncA05Pickers[kind],source=$(c.native);
  if(![...source.options].some(opt=>opt.value===value))return;
  source.value=value;
  ncA05SetPickerOpen(kind,false);
  source.dispatchEvent(new Event('change',{bubbles:true}));
  ncA05SyncPicker(kind,true);
  $(c.toggle).focus({preventScroll:true});
}
function ncA05PickerKeydown(e,kind){
  const menu=$(ncA05Pickers[kind].menu);
  if(e.key==='Escape'){
    e.preventDefault();e.stopPropagation();ncA05SetPickerOpen(kind,false);
    $(ncA05Pickers[kind].toggle).focus();return;
  }
  if(e.key==='Tab'){
    ncA05SetPickerOpen(kind,false);return;
  }
  const options=[...menu.querySelectorAll('[role="option"]')];
  if(!options.length)return;
  const i=options.indexOf(document.activeElement);
  if(['ArrowDown','ArrowUp','Home','End'].includes(e.key)){
    e.preventDefault();
    const next=e.key==='Home'?0:e.key==='End'?options.length-1:e.key==='ArrowDown'?Math.min(i+1,options.length-1):Math.max(i-1,0);
    options[next]?.focus();
  }else if((e.key==='Enter'||e.key===' ')&&i>=0){
    e.preventDefault();ncA05ChooseValue(kind,options[i].dataset.nca05Option);
  }
}

/* A05 bookmark menu is a nonmodal management popover, not a listbox: every
   item has both a 'go to time' action and a separate removal action. */
ncA04RenderBookmarkOptions=function(){
  const native=$('nc32MarkSelect'),toggle=$('ncA04MarkToggle');
  const menu=$('ncA04MarkMenu'),value=$('ncA04MarkValue');
  if(!native||!toggle||!menu||!value)return;
  const marks=nc32Marks(),selected=native.value;
  const current=selected!==''?marks[Number(selected)]:null;
  value.textContent=current?current.name:'Segnalibri ('+marks.length+')';
  toggle.title=current?current.name+' - '+formatTime(current.time,true):'Apri e gestisci i segnalibri';
  toggle.setAttribute('aria-label',current?'Segnalibro selezionato: '+current.name:'Segnalibri ('+marks.length+')');
  toggle.classList.toggle('has-selection',!!current);
  menu.innerHTML='<div class="ncux-proto-menu-caption">SEGNALIBRI DELLA CATTURA <span class="ncA04-mark-total">'+marks.length+'</span></div>'+(
    marks.length?marks.map((mark,index)=>
      '<div class="ncA05-mark-row" data-nca05-row="'+index+'">'+
      '<button type="button" class="ncA04-mark-option" tabindex="0" data-ncA04-mark="'+index+'" aria-current="'+(selected===String(index))+'" title="Vai al tempo '+formatTime(mark.time,true)+'">'+
      '<span class="ncA04-mark-option-icon"><svg aria-hidden="true"><use href="#i-bookmark"/></svg></span>'+
      '<span class="ncA04-mark-option-content"><strong>'+escapeHtml(mark.name)+'</strong><small>'+formatTime(mark.time,true)+'</small></span>'+
      '<span class="ncA04-mark-check" aria-hidden="true"><svg><use href="#i-check"/></svg></span></button>'+
      '<button type="button" class="ncA05-mark-delete" data-nca05-request="'+index+'" aria-label="Elimina il segnalibro '+escapeHtml(mark.name)+'" title="Elimina questo segnalibro"><svg aria-hidden="true"><use href="#i-trash"/></svg></button>'+
      '<div class="ncA05-mark-confirm" role="group" aria-label="Conferma eliminazione segnalibro"><span>Eliminare il segnalibro?</span><button type="button" data-nca05-cancel="'+index+'">Annulla</button><button class="ncA05-confirm-delete" type="button" data-nca05-confirm="'+index+'">Elimina</button></div></div>'
    ).join(''):'<div class="ncA04-mark-empty">Nessun segnalibro.<small>Usa l\'icona con il simbolo + per creare il primo.</small></div>'
  );
  ncA05ConfirmingMark=null;
  if(ncA04MarkMenuOpen)ncA04PositionMarkMenu();
};
ncA04SetMarkMenuOpen=function(open,focusOption=false){
  const menu=$('ncA04MarkMenu'),toggle=$('ncA04MarkToggle');
  if(!menu||!toggle)return;
  if(open)ncA05ClosePickers();
  ncA04MarkMenuOpen=!!open;
  menu.classList.toggle('hidden',!open);
  toggle.setAttribute('aria-expanded',String(!!open));
  ncA05ConfirmingMark=null;
  if(open){
    ncA04RenderBookmarkOptions();
    ncA04PositionMarkMenu();
    if(focusOption){
      (menu.querySelector('.ncA04-mark-option[aria-current="true"]')||menu.querySelector('.ncA04-mark-option'))?.focus();
    }
  }
};
ncA04BookmarkMenuKey=function(e){
  if(e.key==='Escape'){
    e.preventDefault();e.stopPropagation();
    ncA04SetMarkMenuOpen(false);$('ncA04MarkToggle').focus();return;
  }
  const menu=$('ncA04MarkMenu');
  if(e.key==='Tab'){
    // Keep the delete action keyboard-reachable; close only on leaving the popover.
    const controls=[...menu.querySelectorAll('button:not(:disabled)')].filter(x=>getComputedStyle(x).display!=='none'&&x.getClientRects().length);
    const atEdge=e.shiftKey?document.activeElement===controls[0]:document.activeElement===controls[controls.length-1];
    if(atEdge){e.preventDefault();ncA04SetMarkMenuOpen(false);$('ncA04MarkToggle').focus();}
    return;
  }
  const options=[...menu.querySelectorAll('.ncA04-mark-option')];
  if(!options.length)return;
  const row=document.activeElement.closest?.('.ncA05-mark-row');
  const current=row?Number(row.dataset.nca05Row):-1;
  if(['ArrowDown','ArrowUp','Home','End'].includes(e.key)){
    e.preventDefault();
    const next=e.key==='Home'?0:e.key==='End'?options.length-1:e.key==='ArrowDown'?Math.min(current+1,options.length-1):Math.max(current-1,0);
    options[next]?.focus();
  }else if((e.key==='Enter'||e.key===' ')&&document.activeElement.classList?.contains('ncA04-mark-option')){
    e.preventDefault();ncA04SelectBookmark(Number(document.activeElement.dataset.nca04Mark));
  }
};
function ncA05RequestRemove(index){
  const menu=$('ncA04MarkMenu');
  if(!nc32Marks()[index])return;
  ncA05ConfirmingMark=index;
  menu.querySelectorAll('[data-nca05-row]').forEach(row=>row.classList.toggle('is-confirming',Number(row.dataset.nca05Row)===index));
  ncA04PositionMarkMenu();
  menu.querySelector('[data-nca05-confirm="'+index+'"]')?.focus();
}
function ncA05CancelRemove(index){
  ncA05ConfirmingMark=null;
  $('ncA04MarkMenu').querySelectorAll('[data-nca05-row]').forEach(row=>row.classList.remove('is-confirming'));
  ncA04PositionMarkMenu();
  $('ncA04MarkMenu').querySelector('[data-nca05-request="'+index+'"]')?.focus();
}
function ncA05RemoveBookmark(index){
  if(ncA05ConfirmingMark!==index)return;
  const marks=nc32Marks(),old=marks[index];
  if(!old)return;
  const native=$('nc32MarkSelect'),selected=native.value;
  let retained='';
  if(selected!==''&&Number(selected)!==index)retained=String(Number(selected)>index?Number(selected)-1:Number(selected));
  // Clear before the v3.2 renderer so it will not preserve a shifted index.
  native.value='';
  marks.splice(index,1);
  nc31SaveCase();
  nc32RenderMarkOptions();
  native.value=retained;
  $('nc32MarkRemove').disabled=retained==='';
  ncA04RenderBookmarkOptions();
  drawTimeline();
  notify('Segnalibro eliminato',old.name+' - '+formatTime(old.time,true));
  if(marks.length){
    ncA04PositionMarkMenu();
    $('ncA04MarkMenu').querySelector('[data-ncA04-mark="'+Math.min(index,marks.length-1)+'"]')?.focus();
  }else{
    ncA04SetMarkMenuOpen(false);
    $('ncA04MarkToggle').focus();
  }
}
function ncA05BindControls(){
  for(const [kind,c] of Object.entries(ncA05Pickers)){
    const toggle=$(c.toggle),menu=$(c.menu),source=$(c.native);
    document.body.appendChild(menu); // fixed-layer popup above all clipped panels
    source.addEventListener('change',()=>ncA05SyncPicker(kind,true));
    toggle.addEventListener('click',()=>ncA05SetPickerOpen(kind,ncA05OpenPicker!==kind,true));
    toggle.addEventListener('keydown',e=>{
      if(['ArrowDown','ArrowUp','Enter',' '].includes(e.key)){
        e.preventDefault();ncA05SetPickerOpen(kind,true,true);
      }else if(e.key==='Escape')ncA05SetPickerOpen(kind,false);
    });
    menu.addEventListener('keydown',e=>ncA05PickerKeydown(e,kind));
    menu.addEventListener('click',e=>{
      const option=e.target.closest('[data-nca05-option]');
      if(option)ncA05ChooseValue(kind,option.dataset.nca05Option);
    });
    ncA05SyncPicker(kind,true);
  }
  // Retain the original A04 creation modal, replace the detached remove button.
  const marks=$('ncA04MarkMenu');
  marks.addEventListener('click',e=>{
    const remove=e.target.closest('[data-nca05-request]');
    const cancel=e.target.closest('[data-nca05-cancel]');
    const confirm=e.target.closest('[data-nca05-confirm]');
    if(remove){e.preventDefault();ncA05RequestRemove(Number(remove.dataset.nca05Request));}
    else if(cancel){e.preventDefault();ncA05CancelRemove(Number(cancel.dataset.nca05Cancel));}
    else if(confirm){e.preventDefault();ncA05RemoveBookmark(Number(confirm.dataset.nca05Confirm));}
  });
  document.addEventListener('pointerdown',e=>{
    if(ncA05OpenPicker){
      const c=ncA05Pickers[ncA05OpenPicker];
      if(!$(c.toggle).contains(e.target)&&!$(c.menu).contains(e.target))ncA05ClosePickers();
    }
  });
  document.addEventListener('keydown',e=>{
    if(e.key==='Escape'&&ncA05OpenPicker){
      const name=ncA05OpenPicker;
      ncA05ClosePickers();
      $(ncA05Pickers[name].toggle).focus();
    }
  });
  const reposition=()=>{if(ncA05OpenPicker)ncA05PositionPicker(ncA05OpenPicker);};
  window.addEventListener('resize',reposition);
  document.addEventListener('scroll',reposition,true);
}

// Keep custom values in sync with programmatic import and reset operations.
const ncA05PreviousDrawTimeline=drawTimeline;
drawTimeline=function(...args){
  const result=ncA05PreviousDrawTimeline(...args);
  ncA05SyncPicker('metric');
  ncA05SyncPicker('speed');
  ncA05SyncPicker('window');
  return result;
};
const ncA05PreviousWireUI=wireUI;
wireUI=function(){ncA05PreviousWireUI();ncA05BindControls();};
