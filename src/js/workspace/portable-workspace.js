'use strict';
/* NullCap Studio 4.0.1 — portable investigations.
   Standard uncompressed ZIP, entirely offline. The original PCAP bytes are
   embedded unmodified; unlike report exports, the archive MAY contain secrets.
   SHA-256 checks detect corruption/substitution, NOT authenticity/signatures. */
const NC401_FORMAT='NullCap portable forensic workspace';
const NC401_VERSION=1;
const NC401_MANIFEST_NAME='nullcap-manifest.json';
const NC401_MAX_ARCHIVE=NC40_MAX_RAW_BYTES+18*1024*1024;
const NC401_MAX_MANIFEST=16*1024*1024;
const NC401_MAX_ENTRIES=65;
const nc401Encoder=new TextEncoder();
const nc401Decoder=new TextDecoder('utf-8',{fatal:true});
const nc401CRCTable=new Uint32Array(256);
for(let n=0;n<256;n++){let c=n;for(let i=0;i<8;i++)c=(c&1)?0xedb88320^(c>>>1):c>>>1;nc401CRCTable[n]=c>>>0;}
let nc401Working=false;
nc40.portableCases=Object.create(null);
nc40.portableUI=Object.create(null);
function nc401Own(object,key){return Object.prototype.hasOwnProperty.call(object||{},key);}
function nc401Status(message){const el=$('nc401PortableProgress');if(el)el.textContent=message||'';}
function nc401SetBusy(isBusy){nc401Working=isBusy;for(const id of ['nc401SaveWorkspace','nc401OpenWorkspace'])$(id).disabled=isBusy;}
function nc401RememberActive(){
  const id=state.captureId;
  if(!id||nc40.active!==id||!state.investigation||!nc40Slot(id))return;
  state.investigation.aliases=Object.fromEntries(state.hostAliases||[]);
  nc40.portableCases[id]=JSON.parse(JSON.stringify(state.investigation));
  nc40.portableUI[id]={pinned:[...(state.nc32Pinned||new Set())].slice(0,300),subnet:state.nc32Subnet||'ALL',timelineMetric:state.nc32TimelineMetric==='bytes'?'bytes':'packets'};
  nc40.captureNotes[id]=nc40Short(state.investigation.notes||'',8000);
}
const nc401OriginalReadCase=nc31ReadCase;
nc31ReadCase=function(id){return nc401Own(nc40.portableCases,id)?nc40.portableCases[id]:nc401OriginalReadCase(id);};
const nc401OriginalSaveCase=nc31SaveCase;
nc31SaveCase=function(){const result=nc401OriginalSaveCase();nc401RememberActive();return result;};
const nc401OriginalApplyCapture=applyCapture;
applyCapture=function(packets,options={}){
  const incoming=options.captureId||null;
  const preserved=incoming&&nc40.portableUI[incoming]?JSON.parse(JSON.stringify(nc40.portableUI[incoming])):null;
  nc401RememberActive();
  nc401OriginalApplyCapture(packets,options);
  if(preserved)nc40.portableUI[state.captureId]=preserved;
  const ui=nc40.portableUI[state.captureId];
  if(ui){
    state.nc32Pinned=new Set(Array.isArray(ui.pinned)?ui.pinned.filter(x=>typeof x==='string'&&x.length<=160).slice(0,300):[]);
    state.nc32Subnet=typeof ui.subnet==='string'?ui.subnet.slice(0,80):'ALL';
    state.nc32TimelineMetric=ui.timelineMetric==='bytes'?'bytes':'packets';
    $('nc32TimelineMetric').value=state.nc32TimelineMetric;
    nc32SubnetOptions();nc32GraphRefresh();drawTimeline();
  }
};
window.NullCap.applyCapture=applyCapture;
const nc401OriginalRefresh=nc40Refresh;
nc40Refresh=function(){
  nc401OriginalRefresh();
  if(!nc40.expected.some(x=>!nc40Slot(x.id))){
    $('nc40CaseStatus').textContent=`${nc40.captures.length} catture disponibili · Salva Indagine crea un unico ZIP con i PCAP originali e tutti i metadati. Il JSON rimane solo metadati.`;
  }
};
function nc401CRCByte(crc,bytes){for(const b of bytes)crc=nc401CRCTable[(crc^b)&255]^(crc>>>8);return crc>>>0;}
async function nc401CRC(blob){
  const reader=blob.stream().getReader();let crc=0xffffffff,total=0,lastYield=0;
  try{for(;;){const {done,value}=await reader.read();if(done)break;crc=nc401CRCByte(crc,value);total+=value.length;if(total>NC401_MAX_ARCHIVE)throw Error('File troppo grande per il pacchetto portabile');if(total-lastYield>=8*1024*1024){lastYield=total;await new Promise(resolve=>setTimeout(resolve,0));}}}
  finally{reader.releaseLock();}
  return (~crc)>>>0;
}
function nc401U16(view,index,value){view.setUint16(index,value,true);}
function nc401U32(view,index,value){view.setUint32(index,value>>>0,true);}
function nc401Zip(entries){
  // ZIP 2.0, STORE, UTF-8 filenames, no Zip64, no external dependency.
  const chunks=[],central=[];let offset=0,centralLength=0;
  if(entries.length>NC401_MAX_ENTRIES)throw Error('Troppi elementi per il formato ZIP');
  for(const entry of entries){
    const name=nc401Encoder.encode(entry.name),size=entry.blob.size;
    if(name.length>65535||size>0xffffffff||offset+30+name.length+size>0xffffffff)throw Error('Archivio troppo grande per ZIP standard');
    const head=new Uint8Array(30+name.length),h=new DataView(head.buffer);
    nc401U32(h,0,0x04034b50);nc401U16(h,4,20);nc401U16(h,6,0x0800);nc401U16(h,8,0);nc401U16(h,12,0x0021);
    nc401U32(h,14,entry.crc);nc401U32(h,18,size);nc401U32(h,22,size);nc401U16(h,26,name.length);head.set(name,30);
    chunks.push(head,entry.blob);
    const row=new Uint8Array(46+name.length),v=new DataView(row.buffer);
    nc401U32(v,0,0x02014b50);nc401U16(v,4,20);nc401U16(v,6,20);nc401U16(v,8,0x0800);nc401U16(v,10,0);nc401U16(v,14,0x0021);
    nc401U32(v,16,entry.crc);nc401U32(v,20,size);nc401U32(v,24,size);nc401U16(v,28,name.length);nc401U32(v,42,offset);row.set(name,46);
    central.push(row);offset+=head.length+size;centralLength+=row.length;
  }
  if(offset+centralLength+22>0xffffffff)throw Error('Dimensione ZIP fuori limite');
  const end=new Uint8Array(22),v=new DataView(end.buffer);nc401U32(v,0,0x06054b50);nc401U16(v,8,entries.length);nc401U16(v,10,entries.length);nc401U32(v,12,centralLength);nc401U32(v,16,offset);
  return new Blob([...chunks,...central,end],{type:'application/zip'});
}
async function nc401ZipIndex(file){
  if(file.size<22||file.size>NC401_MAX_ARCHIVE)throw Error('Archivio vuoto o oltre il limite di dimensione');
  const tailStart=Math.max(0,file.size-65557),tail=new Uint8Array(await file.slice(tailStart).arrayBuffer()),tailView=new DataView(tail.buffer);let tailPos=-1;
  for(let i=tail.length-22;i>=0;i--)if(tailView.getUint32(i,true)===0x06054b50&&i+22+tailView.getUint16(i+20,true)===tail.length){tailPos=i;break;}
  if(tailPos<0)throw Error('Archivio ZIP non riconosciuto o incompleto');
  const count=tailView.getUint16(tailPos+10,true),centralSize=tailView.getUint32(tailPos+12,true),centralStart=tailView.getUint32(tailPos+16,true);
  if(tailView.getUint16(tailPos+4,true)||tailView.getUint16(tailPos+6,true)||count!==tailView.getUint16(tailPos+8,true)||count>NC401_MAX_ENTRIES)throw Error('Archivio ZIP multi-disco, troppo grande o non supportato');
  if(centralSize>NC401_MAX_MANIFEST||centralStart+centralSize>tailStart+tailPos)throw Error('Indice ZIP non valido');
  const data=new Uint8Array(await file.slice(centralStart,centralStart+centralSize).arrayBuffer()),view=new DataView(data.buffer),entries=new Map();let at=0,total=0;
  for(let i=0;i<count;i++){
    if(at+46>data.length||view.getUint32(at,true)!==0x02014b50)throw Error('Indice ZIP danneggiato');
    const flags=view.getUint16(at+8,true),method=view.getUint16(at+10,true),crc=view.getUint32(at+16,true),comp=view.getUint32(at+20,true),raw=view.getUint32(at+24,true),len=view.getUint16(at+28,true),extra=view.getUint16(at+30,true),comment=view.getUint16(at+32,true),local=view.getUint32(at+42,true);
    if(method!==0||(flags&1)||(flags&8)||raw!==comp)throw Error('ZIP compresso/cifrato non supportato: aprire solo gli archivi creati da NullCap');
    if(at+46+len+extra+comment>data.length)throw Error('Nome file ZIP non valido');
    const name=nc401Decoder.decode(data.subarray(at+46,at+46+len));
    if(!/^(nullcap-manifest\.json|captures\/[a-zA-Z0-9_-]+\.(pcap|pcapng|cap|dump))$/.test(name)||entries.has(name))throw Error('Percorso ZIP non previsto o duplicato');
    if(local+30>centralStart)throw Error('Offset file non valido');
    const header=new DataView(await file.slice(local,local+30).arrayBuffer());
    if(header.getUint32(0,true)!==0x04034b50||header.getUint16(8,true)!==0||header.getUint32(14,true)!==crc||header.getUint32(18,true)!==raw||header.getUint32(22,true)!==raw)throw Error('Intestazione ZIP non coerente');
    const localNameLength=header.getUint16(26,true),localExtra=header.getUint16(28,true),start=local+30+localNameLength+localExtra;
    if(start+raw>centralStart||localNameLength!==len)throw Error('Contenuto ZIP troncato');
    const localName=nc401Decoder.decode(new Uint8Array(await file.slice(local+30,local+30+len).arrayBuffer()));
    if(localName!==name)throw Error('Nome ZIP incoerente');
    entries.set(name,{name,blob:file.slice(start,start+raw),size:raw,crc});
    total+=raw;at+=46+len+extra+comment;
  }
  if(at!==data.length||total>NC401_MAX_ARCHIVE)throw Error('Indice ZIP con dati inattesi');
  return entries;
}
function nc401SafeName(value){return (nc40Short(value,60)||'indagine').normalize('NFKD').replace(/[\u0300-\u036f]/g,'').replace(/[^a-zA-Z0-9_-]+/g,'-').replace(/^-+|-+$/g,'').slice(0,48)||'indagine';}
function nc401CaseMetadata(slot){
  const raw=nc40.portableCases[slot.id]||nc31ReadCase(slot.id)||nc31NewCase(slot.id);
  return JSON.parse(JSON.stringify(raw));
}
function nc401ManifestAndSources(){
  nc401RememberActive();
  if(!nc40.captures.length||nc40.captures.every(x=>x.isDemo))throw Error('Importa almeno una cattura PCAP o PCAPNG originale prima di salvare.');
  const metadata=nc40CaseData(),sources=[],captureSources=[],caseStates={},captureUI={};let size=0;
  for(let i=0;i<nc40.captures.length;i++){
    const slot=nc40.captures[i],files=Array.isArray(slot.sourceFiles)?slot.sourceFiles:[],expected=slot.id.startsWith('sha256-files:')?slot.id.slice(13).split(':'):[];
    if(slot.isDemo||!files.length||files.length!==expected.length||!expected.every(x=>/^[a-f0-9]{64}$/.test(x)))throw Error('Manca il PCAP originale per '+slot.name+'. Reimporta il file sorgente nel Forensic Workspace e riprova.');
    const items=[];
    for(let j=0;j<files.length;j++){
      const file=files[j];if(file.size>MAX_FILE_BYTES)throw Error('Cattura troppo grande: '+file.name);
      size+=file.size;
      const ext=/\.(pcapng|pcap|cap|dump)$/i.exec(file.name)?.[1]?.toLowerCase()||(slot.format.toUpperCase().includes('PCAPNG')?'pcapng':'pcap');
      const path=`captures/c${String(i+1).padStart(2,'0')}-f${String(j+1).padStart(2,'0')}.${ext}`;
      sources.push({path,file,expectedHash:expected[j]});items.push({path,name:file.name,size:file.size,sha256:expected[j]});
    }
    captureSources.push({captureId:slot.id,name:slot.name,format:slot.format,files:items});
    caseStates[slot.id]=nc401CaseMetadata(slot);
    captureUI[slot.id]=nc40.portableUI[slot.id]||{pinned:[],subnet:'ALL',timelineMetric:'packets'};
  }
  if(size>NC40_MAX_RAW_BYTES)throw Error('Catture originali oltre il limite complessivo di 260 MiB');
  const manifest={format:NC401_FORMAT,version:NC401_VERSION,createdAt:new Date().toISOString(),producer:'NullCap Studio 4.0.1',metadata,
    captureSources,caseStates,captureUI,view:{activeCaptureId:nc40.active,tab:nc40.tab,selected:nc40.selected,baseline:$('nc40Baseline').value,candidate:$('nc40Candidate').value,reportHosts:$('nc40ReportHosts').checked,reportNotes:$('nc40ReportNotes').checked},
    disclosure:'ARCHIVIO SENSIBILE. I PCAP/PCAPNG originali sono inclusi integralmente e possono contenere password, cookie, token e dati personali in chiaro. SHA-256 verifica la corrispondenza dei file, ma non certifica la provenienza o la catena di custodia.'};
  return {manifest,sources,size};
}
async function nc401SaveWorkspace(){
  if(nc401Working||nc40.busy||state.nc32ImportRun)return;
  let inputs;
  try{inputs=nc401ManifestAndSources();}catch(e){notify('Impossibile salvare l’indagine',String(e.message||e),true);return;}
  if(!await nc26Confirm('Il file ZIP includerà integralmente tutti i PCAP/PCAPNG originali. Password, token e altri dati sensibili eventualmente presenti nei pacchetti saranno inclusi in chiaro. Condividere soltanto con colleghi autorizzati e attraverso canali protetti. Procedere?'))return;
  nc401SetBusy(true);
  try{
    const entries=[];
    for(let i=0;i<inputs.sources.length;i++){
      const s=inputs.sources[i];nc401Status(`Salvataggio · verifica SHA-256 del file ${i+1}/${inputs.sources.length} · ${s.file.name}`);
      const hash=await nc31HashBuffer(await s.file.arrayBuffer());
      if(hash!==s.expectedHash)throw Error('Hash originale non corrispondente: '+s.file.name+'. Non verrà esportato un archivio incoerente.');
      const crc=await nc401CRC(s.file);entries.push({name:s.path,blob:s.file,crc});
    }
    const bytes=nc401Encoder.encode(JSON.stringify(inputs.manifest,null,2));
    if(bytes.length>NC401_MAX_MANIFEST)throw Error('Troppe annotazioni o etichette per il manifest');
    const manifestBlob=new Blob([bytes],{type:'application/json'}),manifestCRC=nc401CRCByte(0xffffffff,bytes);
    entries.unshift({name:NC401_MANIFEST_NAME,blob:manifestBlob,crc:(~manifestCRC)>>>0});
    nc401Status('Salvataggio · creazione archivio ZIP senza modificare i PCAP...');
    const zip=nc401Zip(entries),filename='NullCap-Indagine-'+nc401SafeName(nc40.title)+'.zip';
    if(zip.size>NC401_MAX_ARCHIVE)throw Error('Archivio oltre il limite supportato');
    const url=URL.createObjectURL(zip),link=document.createElement('a');link.href=url;link.download=filename;document.body.append(link);link.click();link.remove();
    setTimeout(()=>URL.revokeObjectURL(url),120000);
    nc401Status(`Archivio pronto · ${formatBytes(zip.size)} · ${inputs.sources.length} file PCAP/PCAPNG originali`);
    notify('Indagine salvata',`${filename} · ${inputs.sources.length} file sorgente inclusi. Attenzione: contiene i byte originali e può includere segreti in chiaro.`);
  }catch(err){nc401Status('Salvataggio non riuscito');notify('Salvataggio indagine non riuscito',String(err.message||err),true);}
  finally{nc401SetBusy(false);}
}
function nc401ValidateManifest(obj,index){
  if(obj?.format!==NC401_FORMAT||obj.version!==NC401_VERSION||!obj.metadata||!Array.isArray(obj.captureSources)||!obj.caseStates||!obj.captureUI)throw Error('Manifest NullCap non riconosciuto');
  if(obj.captureSources.length<1||obj.captureSources.length>NC40_MAX_CAPTURES)throw Error('Numero di catture non consentito');
  if(obj.metadata.format!==NC40_CASE_FORMAT||obj.metadata.version!==1||!Array.isArray(obj.metadata.captures)||obj.metadata.captures.length!==obj.captureSources.length)throw Error('Metadati del caso non coerenti');
  const seen=new Set();let total=0,filesTotal=0;
  for(let i=0;i<obj.captureSources.length;i++){
    const record=obj.captureSources[i],metadata=obj.metadata.captures[i];
    if(typeof record.captureId!=='string'||!/^sha256-files:([0-9a-f]{64})(:[0-9a-f]{64})*$/.test(record.captureId)||record.captureId.length>600||record.captureId!==metadata.captureId||!Array.isArray(record.files)||record.files.length<1||record.files.length>NC401_MAX_ENTRIES-1)throw Error('Identificativo cattura non valido');
    if(seen.has(record.captureId))throw Error('Cattura duplicata');seen.add(record.captureId);
    const stored=obj.caseStates[record.captureId];
    if(!stored||stored.format!=='NullCap Studio investigation'||stored.version!==1||stored.captureId!==record.captureId||!nc401Own(obj.captureUI,record.captureId))throw Error('Stato investigativo della cattura mancante o non coerente');
    const actual=[];
    for(const source of record.files){
      if(typeof source.name!=='string'||source.name.length>220||typeof source.path!=='string'||typeof source.size!=='number'||typeof source.sha256!=='string'||!/^([a-f0-9]{64})$/.test(source.sha256))throw Error('Descrittore PCAP non valido');
      const entry=index.get(source.path);if(!entry||entry.size!==source.size||entry.size>MAX_FILE_BYTES||entry.size<24)throw Error('File PCAP mancante o dimensione diversa: '+source.name);
      total+=entry.size;filesTotal++;actual.push(source.sha256);
    }
    if('sha256-files:'+actual.join(':')!==record.captureId)throw Error('Hash del gruppo di catture incoerente');
  }
  if(total>NC40_MAX_RAW_BYTES||filesTotal+1!==index.size)throw Error('Archivio troppo grande o con file inattesi');
  return obj;
}
async function nc401OpenWorkspace(file){
  if(!file||nc401Working||nc40.busy||state.nc32ImportRun)return;
  if(nc40.captures.some(x=>!x.isDemo)&&!await nc26Confirm('Aprire il file sostituirà il workspace attualmente aperto in questa scheda. Prima salva l’indagine corrente se contiene modifiche da conservare. Continuare?'))return;
  nc401SetBusy(true);const previousPage=state.page;
  let staged=[];
  try{
    nc401Status('Apertura · controllo struttura ZIP...');
    const index=await nc401ZipIndex(file),manifestEntry=index.get(NC401_MANIFEST_NAME);
    if(!manifestEntry||manifestEntry.size>NC401_MAX_MANIFEST)throw Error('Manifest mancante o troppo grande');
    if(await nc401CRC(manifestEntry.blob)!==manifestEntry.crc)throw Error('Manifest ZIP danneggiato (CRC32)');
    const manifest=nc401ValidateManifest(JSON.parse(await manifestEntry.blob.text()),index);
    const run={cancelled:false,worker:null,activeReject:null};state.nc32ImportRun=run;
    for(let i=0;i<manifest.captureSources.length;i++){
      const record=manifest.captureSources[i],files=[],packets=[],warnings=[],formats=new Set();
      for(let j=0;j<record.files.length;j++){
        const item=record.files[j],entry=index.get(item.path);
        nc401Status(`Apertura · verifica file ${j+1}/${record.files.length} della cattura ${i+1}/${manifest.captureSources.length}: ${item.name}`);
        const bytes=await entry.blob.arrayBuffer();
        if(await nc401CRC(new Blob([bytes]))!==entry.crc)throw Error('Checksum ZIP non corrispondente: '+item.name);
        const sha=await nc31HashBuffer(bytes);
        if(sha!==item.sha256)throw Error('SHA-256 non corrispondente al file originale: '+item.name);
        nc401Status(`Apertura · parsing ${i+1}/${manifest.captureSources.length} · ${item.name}`);
        const {parsed}=await nc32ParseCaptureAsync(bytes,item.name);if(run.cancelled)throw Error('Importazione annullata');
        if(!parsed.packets.length)throw Error('Nessun pacchetto decodificabile: '+item.name);
        const available=MAX_PACKETS-packets.length;if(available>0)packets.push(...parsed.packets.slice(0,available));
        if(parsed.truncated||parsed.packets.length>available)warnings.push('Importazione troncata: '+item.name);
        if(parsed.unsupported)warnings.push(`${parsed.unsupported} frame non decodificati: ${item.name}`);
        if(parsed.undated)warnings.push(`${parsed.undated} frame senza timestamp: ${item.name}`);
        files.push(new File([entry.blob],item.name,{type:'application/octet-stream'}));formats.add(parsed.format);
      }
      staged.push({record,packets,files,warnings,format:[...formats].join(' + ')});
    }
    state.nc32ImportRun=null;
    // Full preflight (ZIP, CRC32, SHA-256, parsing) finished; only now replace.
    const backup={captures:nc40.captures,active:nc40.active,expected:nc40.expected,notes:nc40.captureNotes,annotations:nc40.annotations,cases:nc40.portableCases,ui:nc40.portableUI,title:nc40.title,analyst:nc40.analyst,summary:nc40.summary,dossier:typeof nc24NormalizeDossier==='function'?nc24NormalizeDossier(nc40.dossier):null,tab:nc40.tab,selected:nc40.selected};
    try{
      nc40.captures=[];nc40.active=null;nc40.expected=[];nc40.captureNotes=Object.create(null);nc40.annotations=Object.create(null);
      nc40.portableCases=Object.create(null);nc40.portableUI=Object.create(null);
      const data=manifest.metadata;
      nc40.title=nc40Short(data.case?.title,100)||'Indagine senza titolo';
      nc40.analyst=nc40Short(data.case?.analyst,100);nc40.summary=nc40Short(data.case?.summary,5000);
      if(typeof nc24NormalizeDossier==='function')nc40.dossier=nc24NormalizeDossier(data.dossier);
      for(const [id,value] of Object.entries(manifest.caseStates).slice(0,NC40_MAX_CAPTURES))if(manifest.captureSources.some(x=>x.captureId===id)&&value&&typeof value==='object')nc40.portableCases[id]=value;
      for(const [id,value] of Object.entries(manifest.captureUI).slice(0,NC40_MAX_CAPTURES))if(manifest.captureSources.some(x=>x.captureId===id)&&value&&typeof value==='object')nc40.portableUI[id]=value;
      for(const [key,val] of Object.entries(data.annotations||{}).slice(0,500))if(typeof val==='string'&&key.length<800)nc40.annotations[key]=nc40Short(val,1200);
      for(const item of data.captures){if(typeof item.captureNotes==='string')nc40.captureNotes[item.captureId]=nc40Short(item.captureNotes,8000);}
      for(let i=0;i<staged.length;i++){
        const s=staged[i];nc401Status(`Apertura · ripristino cattura ${i+1}/${staged.length}`);
        applyCapture(s.packets,{name:s.record.name||s.files.map(x=>x.name).join(', '),format:s.record.format||s.format,captureId:s.record.captureId,warnings:s.warnings,sourceFiles:s.files});
      }
      const view=manifest.view||{},active=nc40Slot(view.activeCaptureId)?view.activeCaptureId:nc40.captures[0].id;
      if(nc40.active!==active)nc40Activate(active,false);
      nc40.tab=['events','signals','compare','report'].includes(view.tab)?view.tab:'events';
      nc40.selected=typeof view.selected==='string'&&view.selected.length<800?view.selected:null;
      nc40RestoreFields();if(typeof nc24ImportDossier==='function')nc24ImportDossier(data.dossier);nc40Refresh();
      if(nc40Slot(view.baseline))$('nc40Baseline').value=view.baseline;
      if(nc40Slot(view.candidate))$('nc40Candidate').value=view.candidate;
      $('nc40ReportHosts').checked=view.reportHosts!==false;
      $('nc40ReportNotes').checked=view.reportNotes!==false;
      nc40SetTab(nc40.tab);setPage('forensic');
      nc401Status(`Indagine aperta · ${staged.length} catture originali verificate e ripristinate`);
      notify('Indagine aperta',`${nc40.title} · ${staged.length} catture PCAP/PCAPNG integrate, con note ed etichette.`,false);
    }catch(err){
      Object.assign(nc40,{captures:backup.captures,active:backup.active,expected:backup.expected,captureNotes:backup.notes,annotations:backup.annotations,portableCases:backup.cases,portableUI:backup.ui,title:backup.title,analyst:backup.analyst,summary:backup.summary,dossier:backup.dossier,tab:backup.tab,selected:backup.selected});
      if(nc40Slot(backup.active))nc40Activate(backup.active,false);
      nc40RestoreFields();nc40Refresh();setPage(previousPage);throw err;
    }
  }catch(err){nc401Status('Apertura non riuscita: il file o i metadati non sono stati accettati');notify('Impossibile aprire l’indagine',String(err?.message||err),true);}
  finally{state.nc32ImportRun=null;nc401SetBusy(false);$('nc32ImportBar')?.classList.add('hidden');}
}
const nc401OriginalWireUI=wireUI;
wireUI=function(){nc401OriginalWireUI();
  $('nc401SaveWorkspace').onclick=nc401SaveWorkspace;
  $('nc401OpenWorkspace').onclick=()=>$('nc401OpenWorkspaceFile').click();
  $('nc401OpenWorkspaceFile').onchange=async e=>{const file=e.target.files[0];e.target.value='';await nc401OpenWorkspace(file);};
};
Object.assign(window.NullCap.forensic,{savePortable:nc401SaveWorkspace,openPortable:nc401OpenWorkspace,portableZipIndex:nc401ZipIndex});
