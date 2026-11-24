'use strict';
/* A12: deterministic, gap-aware, sequence-based forensic TCP reassembly. */
const NC31_STREAM_SIDE_LIMIT=NullCapTCPReassembler.SIDE_LIMIT;
const NC31_STREAM_RENDER_INITIAL=140000;
const NC31_STREAM_RENDER_STEP=140000;
let nc31Stream=null,nc31StreamRenderBudget=NC31_STREAM_RENDER_INITIAL;
function nc31SelectedSession(packet){
  return nc31BuildStream(packet).session;
}
function nc31BuildStream(packet){
  return NullCapTCPReassembler.createStream(state.packets,packet,
    {sideLimit:NC31_STREAM_SIDE_LIMIT,isDemo:state.isDemo});
}
function nc31ReadableBytes(bytes,mode){
  if(mode==='hex'){
    const lines=[];
    for(let i=0;i<bytes.length;i+=16){const part=bytes.subarray(i,i+16);
      lines.push(Array.from(part,c=>c.toString(16).padStart(2,'0')).join(' ')+'   '+Array.from(part,c=>c>=32&&c<=126?String.fromCharCode(c):'.').join(''));
    }return lines.join('\n');
  }
  return new TextDecoder('utf-8',{fatal:false}).decode(bytes).replace(/\u0000/g,'\u00b7');
}
function nc31RenderStream(){
  const stream=nc31Stream;if(!stream)return;
  const dir=$('streamDirection').value,mode=$('streamMode').value,content=$('streamContent');
  const data=stream.events.filter(x=>dir==='both'||x.dir===dir);
  content.replaceChildren();let budget=nc31StreamRenderBudget,shown=0,remaining=false,rows=0;
  for(const event of data){
    if(rows++>=280){remaining=true;break;}
    if(event.kind==='gap'){
      const line=document.createElement('div');line.className='nc31-stream-gap';line.textContent=(event.dir==='a'?'A - B':'B - A')+' | LACUNA '+formatN(event.size)+' byte | prima del frame #'+event.packetId;
      content.append(line);continue;
    }
    if(budget<=0){remaining=true;break;}
    const max=mode==='hex'?Math.floor(budget/4):budget;
    if(max<16){remaining=true;break;}
    const slice=event.bytes.subarray(0,Math.min(event.bytes.length,max));
    const btn=document.createElement('button');btn.type='button';btn.className='nc31-stream-segment'+(event.dir==='b'?' reverse':'');btn.dataset.streamPacket=String(event.packetId);
    const heading=document.createElement('div');heading.className='nc31-segment-meta';
    heading.textContent=(event.dir==='a'?'A - B':'B - A')+' | frame #'+event.packetId+' | '+formatN(event.bytes.length)+' B'+(Number.isFinite(event.rel)?' | T+'+formatTime(event.rel,true):' | tempo N/D');
    const pre=document.createElement('pre');pre.textContent=nc31ReadableBytes(slice,mode);
    btn.append(heading,pre);btn.addEventListener('click',()=>{nc31CloseStream();openPacketById(event.packetId);});content.append(btn);
    shown+=slice.length;budget-=mode==='hex'?slice.length*4:slice.length;
    if(slice.length<event.bytes.length){remaining=true;break;}
  }
  if(!shown&&!data.some(x=>x.kind==='gap')){const empty=document.createElement('div');empty.className='nc31-stream-empty';empty.textContent='Non sono presenti byte applicativi in questa direzione.';content.append(empty);}
  $('streamShowMore').classList.toggle('hidden',!remaining);
}
function nc31OpenStream(packet){
  if(!packet||packet.transport!=='TCP'){notify('Solo stream TCP','Seleziona un pacchetto o una conversazione TCP.',true);return;}
  try{nc31Stream=nc31BuildStream(packet);}catch(err){notify('Stream non disponibile',String(err.message||err),true);return;}
  nc31StreamRenderBudget=NC31_STREAM_RENDER_INITIAL;
  const x=nc31Stream;$('streamRoute').textContent=`A ${x.a.ip}:${x.a.port}   <->   B ${x.b.ip}:${x.b.port}`;
  $('streamStats').textContent=`${x.counters.packets} frame | A - B ${formatBytes(x.limits.a)} | B - A ${formatBytes(x.limits.b)}`;
  $('streamDirection').value='both';$('streamMode').value='ascii';
  $('streamWarnings').textContent=x.warnings.join('  |  ');
  $('streamModal').classList.remove('hidden');nc31RenderStream();$('streamClose').focus();
}
function nc31CloseStream(){nc31Stream=null;$('streamModal').classList.add('hidden');}
function nc31DownloadStream(dir){
  if(!nc31Stream)return;
  const parts=nc31Stream.assembled[dir];if(!parts.length){notify('Nessun dato applicativo','Questa direzione non contiene payload.',true);return;}
  const name=`nullcap-tcp-${dir}-${nc31Stream.session[0].id}.bin`;
  nc31DownloadFile(new Blob(parts,{type:'application/octet-stream'}),name);
  notify('Payload esportato',name+' | '+formatBytes(nc31Stream.limits[dir]));
}
