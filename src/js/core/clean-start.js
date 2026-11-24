'use strict';
/* A27.1 — Clean production startup. Never manufacture a capture or register
   a dummy case. The synthetic generator remains available only to test suites. */
function nc271SyncEmptyState(){
  const hasPackets=state.packets.length>0;
  const empty=!hasPackets;
  document.body.classList.toggle('nc271-no-capture',empty);
  const landing=$('nc271EmptyLanding');
  if(landing)landing.hidden=!empty;
  const dashboard=$('nc271OverviewGrid');
  if(dashboard)dashboard.hidden=empty;
  const source=$('sourceCard');
  if(source)source.classList.toggle('hidden',empty);
  for(const id of ['exportCapture','exportBtn','playBtn','firstBtn','stepBtn','emptyPlay']){
    const button=$(id);
    if(button){button.disabled=empty;button.title=empty?'Importa una cattura per utilizzare questa funzione':'';}
  }
  if(empty){
    const emptyGraph=$('graphEmpty');
    if(emptyGraph){
      const title=emptyGraph.querySelector('strong'),detail=emptyGraph.querySelector('p');
      if(title)title.textContent='Nessuna acquisizione caricata';
      if(detail)detail.textContent='Importa un file PCAP o PCAPNG per visualizzare le comunicazioni.';
    }
    const scan=$('lootScanStatus');
    if(scan)scan.textContent='NESSUNA ACQUISIZIONE';
  }
}
function nc271InitializeEmptyWorkspace(){
  // No applyCapture([]): doing that would register a false capture with the
  // investigation and trigger the artifact scanner and workspace autosaves.
  state.source='';state.format='';state.isDemo=false;
  state.captureId=null;state.investigation=null;
  state.lootStatus='idle';state.loot=[];state.httpEvents=[];
  state.playhead=0;state.duration=0;state.bytes=0;state.undatedCount=0;
  indexCapture();
  updateOverview();buildTracks();renderProtocolFilters();resetSearchOptions();
  setPage('overview',false);renderAll(true);
  nc40Refresh();nc24RenderDossier();nc271SyncEmptyState();
}
// All capture entry points (sidebar/top bar, forensic import and ZIP restore)
// already flow through applyCapture; refresh only the empty-state presentation.
const nc271PreviousUpdateOverview=updateOverview;
updateOverview=function(...args){
  const result=nc271PreviousUpdateOverview(...args);
  nc271SyncEmptyState();
  return result;
};
const nc271PreviousWireUI=wireUI;
wireUI=function(){
  nc271PreviousWireUI();
  $('nc271ImportCapture').addEventListener('click',()=>$('fileInput').click());
  $('nc271OpenInvestigation').addEventListener('click',()=>$('nc401OpenWorkspaceFile').click());
};
