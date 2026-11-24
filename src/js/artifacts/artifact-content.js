'use strict';
/* A20 - Content-first Artifact Inspector, based on approved Solution A.
 * This module rearranges existing nodes AFTER the A19 renderer. It deliberately
 * preserves existing asset bytes, DOM event handlers, source references, audio
 * players and asynchronous SHA-256 updates. No capture/parsing logic changes.
 */
function nc20ContentFirstInspector(){
  const host=document.getElementById('lootDetail');
  const asset=(state.loot||[]).find(a=>a.id===state.selectedLoot);
  if(!host||!asset)return;

  const identity=host.querySelector('.nc19-summary');
  const provenance=host.querySelector('.nc19-section:not(.nc19-quality):not(.nc19-preview-section)');
  const actions=provenance?.querySelector('.nc19-actionbar');
  const quality=host.querySelector('.nc19-quality');
  const preview=host.querySelector('.nc19-preview-section');
  const technical=host.querySelector('.nc19-technical');
  if(!identity||!provenance||!actions||!quality||!preview||!technical)return;

  identity.classList.add('nc20-identity');
  provenance.classList.add('nc20-provenance');
  preview.classList.add('nc20-preview');
  technical.classList.add('nc20-technical');
  quality.classList.add('nc20-quality');

  // Keep the existing fact elements but remove the nested card visual treatment.
  const facts=identity.querySelector('.nc19-summary-facts');
  if(facts)facts.classList.add('nc20-meta');

  // Action controls are the original buttons; only their VISUAL labels change.
  // Keep id, aria-label, onclick, disabled state, and the shared mail-search SVG.
  actions.classList.add('nc20-actions');
  actions.querySelector('.nc19-action-label')?.remove();
  const actionRow=actions.querySelector('.loot-action-row');
  if(actionRow){
    for(const [id,label] of [['lootDownload','Scarica'],['lootInspectPacket','Apri pacchetto']]){
      const button=actionRow.querySelector('#'+id);
      if(!button)continue;
      button.classList.add('nc20-action');
      button.removeAttribute('data-tip'); // Label is now visible, not just a tooltip.
      const existing=button.querySelector('.nc20-action-text');
      if(existing)existing.remove();
      const caption=document.createElement('span');
      caption.className='nc20-action-text';
      caption.textContent=label;
      button.append(caption);
    }
  }

  // Keep the original local, source-derived preview and its interactive player.
  const previewTitle=preview.querySelector('.nc19-section-heading');
  if(previewTitle){
    previewTitle.textContent='';
    previewTitle.insertAdjacentHTML('afterbegin',ncIcon('eye'));
    previewTitle.append(document.createTextNode('Anteprima'));
  }

  // For normal findings, leave the full qualifying forensic note one click away.
  // For partial, ambiguous or sensitive findings, expand it and surface it BEFORE
  // the preview, so the user cannot mistake the extracted content for certainty.
  const warning=quality.querySelector('.nc312-secret-warning');
  const explanation=quality.querySelector('.nc16-proof');
  const secondaryNote=quality.querySelector('.nc313-secondary-note');
  const oldHeading=quality.querySelector('.nc19-section-heading');
  const oldCaption=quality.querySelector('.nc19-quality-caption');
  const sourceQuality=nc16Quality(asset);
  quality.classList.add('nc20-quality-'+sourceQuality);
  const important=(sourceQuality!=='complete'||!!warning);
  quality.classList.toggle('nc20-quality-important',important);

  const disclosure=document.createElement('details');
  disclosure.className='nc20-quality-disclosure';
  if(important)disclosure.open=true;
  const trigger=document.createElement('summary');
  trigger.className='nc20-quality-trigger';
  if(oldHeading){oldHeading.classList.add('nc20-quality-heading');trigger.append(oldHeading);}
  if(oldCaption){
    oldCaption.classList.add('nc20-quality-caption');
    const label=oldCaption.querySelector('strong');
    if(label){
      label.textContent=sourceQuality==='ambiguous'?'SOVRAPPOSIZIONI AMBIGUE':
        sourceQuality==='partial'?'RICOSTRUZIONE PARZIALE':
        'NESSUNA LACUNA NEI BYTE ESTRATTI';
    }
    trigger.append(oldCaption);
  }
  const caret=document.createElement('span');
  caret.className='nc20-quality-caret';
  caret.innerHTML=ncIcon('chevrondown');
  trigger.append(caret);
  disclosure.append(trigger);
  if(explanation)disclosure.append(explanation);
  if(secondaryNote)disclosure.append(secondaryNote);
  quality.replaceChildren();
  if(warning){
    warning.classList.add('nc20-priority-warning');
    quality.append(warning);
  }
  quality.append(disclosure);

  // Content-first order: identify > act > preview > provenance > quality > detail.
  // Exception: material quality warnings precede the preview, without duplication.
  host.replaceChildren(...(important?
    [identity,actions,quality,preview,provenance,technical]:
    [identity,actions,preview,provenance,quality,technical]));
  host.classList.add('nc20-content-first');
  host.scrollTop=0; // Selecting a new artifact always starts at its identity.
}
const nc20PreviousRenderLootDetail=ncRenderLootDetail;
ncRenderLootDetail=function(){
  nc20PreviousRenderLootDetail();
  nc20ContentFirstInspector();
};
