'use strict';
/* A06: UI-only adapter. The A05 picker handles #windowSeconds with all the
   same keyboard, focus, outside-click and synchronized-native behavior. */
const ncA06OldWindowVisibility=ncA04SyncWindowVisibility;
ncA04SyncWindowVisibility=function(){
  ncA06OldWindowVisibility();
  // A floating menu must never remain visible when its trigger disappears.
  if(state.mode!=='window'&&ncA05OpenPicker==='window')ncA05ClosePickers();
};
