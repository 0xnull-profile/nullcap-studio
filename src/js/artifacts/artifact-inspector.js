'use strict';
/* A19 · Bottino detail hierarchy, presentation only.
 * Retain the A16 renderer, data provenance, hash promise, original preview and
 * all download/frame-link handlers. Reparent existing interactive elements.
 */
function nc19Node(tag,className,text){
  const node=document.createElement(tag);
  if(className)node.className=className;
  if(text!==undefined)node.textContent=text;
  return node;
}
function nc19Section(label,icon=''){
  const section=nc19Node('section','nc19-section');
  const heading=nc19Node('h4','nc19-section-heading');
  if(icon)heading.innerHTML=ncIcon(icon);
  heading.append(document.createTextNode(label));
  section.append(heading);
  return section;
}
function nc19ReorganizeArtifact(){
  const host=document.getElementById('lootDetail');
  const asset=(state.loot||[]).find(a=>a.id===state.selectedLoot);
  if(!host||!asset)return;
  const header=host.querySelector('.loot-detail-header');
  const title=host.querySelector('h3');
  const description=title?.nextElementSibling?.matches('p')?title.nextElementSibling:null;
  const oldOrigin=host.querySelector('.nc16-origin');
  const hash=oldOrigin?.querySelector('.nc16-hash');
  const actions=host.querySelector('.loot-action-row');
  const proof=host.querySelector('.nc16-proof');
  const sensitive=host.querySelector('.nc312-secret-warning');
  const secondary=host.querySelector('.nc313-secondary-note');
  const metadata=host.querySelector('.loot-info-list');
  const authEvidence=host.querySelector('.nc313-evidence-panel');
  const preview=host.querySelector('#lootPreview');
  if(!header||!title||!oldOrigin||!actions||!proof||!metadata||!preview)return;

  const quality=nc16Quality(asset);
  const qualityLabel=quality==='ambiguous'?'AMBIGUO':quality==='partial'?'PARZIALE':'NESSUNA LACUNA RILEVATA';
  // A16 status is based on the artifact, not on stream quality: avoid showing
  // "COMPLETO" when TCP source bytes are ambiguous.
  const headlineStatus=header.querySelector('.loot-status');
  if(headlineStatus&&!asset.authFinding&&quality==='ambiguous'){
    headlineStatus.textContent='AMBIGUO';headlineStatus.classList.add('nc16-ambiguous');
  }

  const summary=nc19Node('section','nc19-summary');
  summary.append(header,title);
  if(description)summary.append(description);
  const facts=nc19Node('div','nc19-summary-facts');
  const createFact=(label,value)=>{
    const fact=nc19Node('div','nc19-fact');
    fact.append(nc19Node('small','',label),nc19Node('strong','',value));
    return fact;
  };
  facts.append(createFact('DIMENSIONE',formatBytes(asset.data?.length||0)));
  if(asset.authFinding){
    facts.append(createFact('ESITO AUTENTICAZIONE',nc312OutcomeLabel(asset)));
  }else{
    facts.append(createFact('FORMATO',asset.contentType||'Non dichiarato'));
  }
  summary.append(facts);

  const sourceSection=nc19Section('Provenienza osservata','network');
  const sourceCard=nc19Node('div','nc16-origin nc19-source-card');
  const endpoints=nc19Node('div','nc19-endpoints');
  for(const [label,value] of [['SORGENTE',asset.src||'N/D'],['DESTINAZIONE',asset.dst||'N/D']]){
    if(label==='DESTINAZIONE'){
      const arrow=nc19Node('span','nc19-source-arrow');arrow.innerHTML=ncIcon('arrow-right');endpoints.append(arrow);
    }
    const endpoint=nc19Node('div','nc19-endpoint');
    endpoint.append(nc19Node('small','',label),nc19Node('strong','',String(value)));
    endpoints.append(endpoint);
  }
  const sourceMeta=nc19Node('div','nc19-source-meta');
  sourceMeta.append(nc19Node('span','',formatN(asset.packetIds?.length||0)+' frame associati'));
  sourceMeta.append(nc19Node('span','',
    'Primo #'+(asset.packetIds?.[0]??'N/D')));
  sourceMeta.append(nc19Node('span','',Number.isFinite(asset.rel)?'T+'+formatTime(asset.rel,true):'Timestamp N/D'));
  sourceCard.append(endpoints,sourceMeta);
  sourceSection.append(sourceCard);
  const actionBar=nc19Node('div','nc19-actionbar');
  actionBar.append(nc19Node('span','nc19-action-label','AZIONI RAPIDE'),actions);
  sourceSection.append(actionBar);

  const qualitySection=nc19Section('Qualità dell’evidenza','shield');
  qualitySection.classList.add('nc19-quality','nc19-quality-'+quality);
  const qualityLine=nc19Node('div','nc19-quality-caption');
  qualityLine.append(nc19Node('span','nc19-quality-dot'));
  qualityLine.append(nc19Node('strong','',qualityLabel));
  qualitySection.append(qualityLine);
  if(sensitive)qualitySection.append(sensitive);
  if(secondary)qualitySection.append(secondary);
  qualitySection.append(proof);

  const previewSection=nc19Section('Anteprima dell’artefatto','eye');
  previewSection.classList.add('nc19-preview-section');
  previewSection.append(preview);

  const technical=nc19Node('details','nc19-technical');
  const trigger=nc19Node('summary','nc19-technical-trigger');
  const detailTitle=nc19Node('span','');
  detailTitle.innerHTML=ncIcon('file-text');
  detailTitle.append(document.createTextNode('Dettagli tecnici e integrità'));
  trigger.append(detailTitle);
  trigger.insertAdjacentHTML('beforeend',ncIcon('chevrondown'));
  technical.append(trigger);
  const detailBody=nc19Node('div','nc19-technical-body');
  // Remove only data already displayed in the identity/provenance summary.
  const shownAbove=new Set(['Dimensioni','Valori sensibili','Esito autenticazione','Primo evento','Sorgente','Destinazione','Pacchetti associati']);
  for(const row of metadata.querySelectorAll('.loot-info-row')){
    if(shownAbove.has(row.querySelector('span')?.textContent.trim()))row.remove();
  }
  detailBody.append(metadata);
  if(hash)detailBody.append(hash); // Same async SHA-256 node from A16, no recomputation.
  if(authEvidence)detailBody.append(authEvidence); // Keep clickable original frame references.
  technical.append(detailBody);

  host.replaceChildren(summary,sourceSection,qualitySection,previewSection,technical);
}
const nc19OriginalRenderLootDetail=ncRenderLootDetail;
ncRenderLootDetail=function(){
  nc19OriginalRenderLootDetail();
  nc19ReorganizeArtifact();
};
