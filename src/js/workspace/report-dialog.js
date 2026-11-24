'use strict';
/* A26: source-preserving dossier layout + independent offline report modal. */
function nc26OpenReport(){
  const tab=nc26El('nc40TabReport'),mount=nc26El('nc26ReportMount');
  if(tab.parentElement!==mount)mount.append(tab);
  tab.classList.remove('hidden');
  nc40SaveFields();
  nc40RenderReportPreview();
  nc26OpenOverlay('nc26ReportModal');
}
function nc26Wire(){
  nc26WireSystemModal();
  nc26El('nc26OpenReport').onclick=nc26OpenReport;
  nc26El('nc26CloseReport').onclick=nc26CloseReport;
  nc26El('nc26ReportDismiss').onclick=nc26CloseReport;
  nc26El('nc26PreviewDismiss').onclick=nc26ClosePreview;
  nc26El('nc24ClosePreview').onclick=nc26ClosePreview;
  document.querySelectorAll('[data-nc26-dismiss]').forEach(el=>el.addEventListener('click',()=>{
    const target=el.dataset.nc26Dismiss;
    if(target==='preview')nc26ClosePreview();
    if(target==='report')nc26CloseReport();
  }));
}
const nc26PreviousWire=wireUI;
wireUI=function(){nc26PreviousWire();nc26Wire();};
