'use strict';
/* 3.2: byte-bounded, read-only protocol decoders. No network requests, no decryption.
   A field is displayed only when its originating bytes exist in the packet. */
const NC32_DECODER_LIMIT=32768;
function nc32Ascii(bytes,limit=1024){return Array.from(bytes.subarray(0,limit),v=>(v>=32&&v<127)||v===10||v===13||v===9?String.fromCharCode(v):'.').join('');}
function nc32Field(name,value,off,len){return {name,value:String(value),off,len:Math.max(1,len||1)};}
function nc32DnsName(b,start,end,depth=0,visited=new Set()){
  if(depth>12||start>=end)return null;
  let at=start,next=start,labels=[],jumped=false;
  for(let i=0;i<70&&at<end;i++){
    if(visited.has(at))return null;visited.add(at);
    const k=b[at];
    if(k===0){if(!jumped)next=at+1;return {name:labels.join('.')||'.',next};}
    if((k&0xc0)===0xc0){if(at+1>=end)return null;const ptr=((k&63)<<8)|b[at+1];if(ptr>=end)return null;if(!jumped)next=at+2;jumped=true;at=ptr;continue;}
    if(k>63||k===0||(k&0xc0)||at+1+k>end)return null;
    labels.push(nc32Ascii(b.subarray(at+1,at+1+k),k));at+=k+1;if(!jumped)next=at;
    if(labels.join('.').length>253)return null;
  }
  return null;
}
function nc32DnsMessage(data,absolute){
  if(data.length<12)return null;const u16=o=>read16(data,o),qr=!!(data[2]&128);
  const fields=[nc32Field('Transaction ID','0x'+u16(0).toString(16).padStart(4,'0'),absolute,2),nc32Field('Tipo',qr?'Risposta':'Richiesta',absolute+2,2),nc32Field('RCode',(data[3]&15)+'',absolute+3,1),nc32Field('Domande',u16(4),absolute+4,2),nc32Field('Risposte',u16(6),absolute+6,2)];
  let ptr=12,seen=0,truncated=false;
  const getName=()=>{const v=nc32DnsName(data,ptr,data.length);if(!v)return null;ptr=v.next;return v.name;};
  const questions=Math.min(u16(4),35);
  for(let i=0;i<questions;i++){const start=ptr,name=getName();if(name===null||ptr+4>data.length){truncated=true;break;}fields.push(nc32Field('Q'+(i+1)+' · Nome',name,absolute+start,ptr-start));fields.push(nc32Field('Q'+(i+1)+' · Tipo',u16(ptr),absolute+ptr,2));ptr+=4;seen++;}
  const rrKinds=['Risposta','Autorità','Aggiuntivo'],rrCounts=[u16(6),u16(8),u16(10)];
  for(let section=0;section<3&&!truncated;section++)for(let i=0;i<Math.min(rrCounts[section],45);i++){
    const start=ptr,name=getName();if(name===null||ptr+10>data.length){truncated=true;break;}
    const type=u16(ptr),cl=u16(ptr+2),ttl=read32(data,ptr+4),length=u16(ptr+8),at=ptr+10,end=at+length;ptr=end;if(end>data.length){truncated=true;break;}
    let value='RDATA '+length+' B';
    if(type===1&&length===4)value=ipv4(data,at);
    else if(type===28&&length===16)value=ipv6(data,at);
    else if([2,5,12,39].includes(type)){value=nc32DnsName(data,at,data.length)?.name||value;}
    else if(type===15&&length>=3)value='preferenza '+read16(data,at)+' · '+(nc32DnsName(data,at+2,data.length)?.name||'?');
    else if(type===16&&length>=1){let t=at,texts=[];while(t<end&&texts.length<6){const len=data[t++];if(t+len>end)break;texts.push(nc32Ascii(data.subarray(t,t+len),240));t+=len;}value=texts.join(' | ').slice(0,340);}
    fields.push(nc32Field(rrKinds[section]+' '+(i+1)+' · '+name,`tipo ${type} · TTL ${ttl}s · ${value}`,absolute+start,end-start));
    seen++;if(seen>120)break;
  }
  if(truncated)fields.push(nc32Field('Integrità','Dati DNS troncati o non decodificabili',absolute,1));
  return {name:'DNS · Analisi dettagliata',description:'Campi e record estratti dai byte del messaggio; compressione dei nomi gestita con controlli di cicli',off:absolute,len:data.length,fields};
}
function nc32TlsHello(data,absolute){
  if(data.length<9||data[0]!==22||data[1]!==3||data[2]>4)return null;
  const reclen=read16(data,3),limit=Math.min(data.length,5+reclen);
  const kind=data[5],hslen=data[6]*65536+data[7]*256+data[8];
  if(kind!==1||hslen+9>limit)return null; // cannot claim a complete hello if split across segments
  let at=9,fields=[nc32Field('Handshake','ClientHello · TLS',absolute+5,4)];
  if(at+34>limit)return null;
  fields.push(nc32Field('Legacy ClientHello version','0x'+read16(data,at).toString(16),absolute+at,2));at+=34;
  if(at>=limit)return null;let sid=data[at++];if(at+sid+2>limit)return null;at+=sid;
  let ciphers=read16(data,at);at+=2;if(ciphers%2||at+ciphers+1>limit)return null;
  fields.push(nc32Field('Cipher suite proposte',ciphers/2,absolute+at-2,2));at+=ciphers;
  let methods=data[at++];if(at+methods+2>limit)return {name:'TLS · ClientHello',description:'Header decodificato, estensioni non complete',off:absolute,len:limit,fields};at+=methods;
  const extTotal=read16(data,at);at+=2;const end=Math.min(limit,at+extTotal);let ct=0;
  while(at+4<=end&&ct++<75){const typ=read16(data,at),len=read16(data,at+2),start=at+4,stop=start+len;if(stop>end)break;
    if(typ===0&&len>=5){let pos=start+2;while(pos+3<=stop){const t=data[pos],n=read16(data,pos+1);pos+=3;if(pos+n>stop)break;if(t===0)fields.push(nc32Field('SNI (server name)',nc32Ascii(data.subarray(pos,pos+n),250),absolute+pos,n));pos+=n;}}
    if(typ===16&&len>=2){let pos=start+2,items=[];while(pos<stop&&items.length<12){const n=data[pos++];if(n===0||pos+n>stop)break;items.push(nc32Ascii(data.subarray(pos,pos+n),90));pos+=n;}if(items.length)fields.push(nc32Field('ALPN',items.join(', '),absolute+start,len));}
    if(typ===43&&len>=3){const n=data[start],vers=[];for(let x=start+1;x+1<Math.min(stop,start+1+n);x+=2)vers.push('0x'+read16(data,x).toString(16));if(vers.length)fields.push(nc32Field('Versioni TLS offerte',vers.join(', '),absolute+start,len));}
    at=stop;
  }
  fields.push(nc32Field('Limite decodifica','ClientHello presente in questo singolo segmento; non verifica certificati o cifratura',absolute+5,1));
  return {name:'TLS · ClientHello',description:'SNI e ALPN osservati in chiaro nel ClientHello, quando interamente presente',off:absolute,len:limit,fields};
}
function nc32HttpHeaders(data,absolute){
  if(!data.length)return null;const txt=nc32Ascii(data,Math.min(NC32_DECODER_LIMIT,data.length));
  let delim=txt.indexOf('\r\n\r\n'),split=4;if(delim<0){delim=txt.indexOf('\n\n');split=2;}if(delim<0)return null;
  const head=txt.slice(0,delim),lines=head.split(/\r?\n/),start=lines.shift()||'';
  if(!/^(?:GET|POST|PUT|PATCH|HEAD|OPTIONS|DELETE|TRACE|CONNECT)\s+\S+\s+HTTP\/1\.[01]$|^HTTP\/1\.[01]\s+\d{3}/.test(start))return null;
  const fields=[nc32Field('Linea iniziale',start,absolute,Math.min(300,start.length))];
  const useful=new Set(['host','content-type','content-length','location','user-agent','server','cache-control','transfer-encoding','authorization','cookie','set-cookie','www-authenticate']);
  let off=start.length+2;
  for(const line of lines.slice(0,60)){
    const idx=line.indexOf(':');if(idx>0){const key=line.slice(0,idx).trim(),low=key.toLowerCase();if(useful.has(low)){
      let value=line.slice(idx+1).trim();
      if(low==='authorization')value=value.split(/\s/)[0]+' (segreto consultabile nei byte originali)';
      else if(low==='cookie'||low==='set-cookie')value=value.split(';').slice(0,4).map(part=>part.trim().split('=')[0]).join('; ')+' (valori omessi dall’anteprima)';
      fields.push(nc32Field(key,value.slice(0,320),absolute+off,Math.min(line.length,320)));
    }}off+=line.length+2;
  }
  fields.push(nc32Field('Header terminati',delim+split+' byte; corpo non decifrato/interpretato qui',absolute+delim,split));
  return {name:'HTTP/1.x · Header',description:'Richiesta/risposta e intestazioni osservate in chiaro; valori sensibili disponibili nel Bottino',off:absolute,len:Math.min(data.length,delim+split),fields};
}
function nc32ProtocolLayers(packet,layers){
  if(!packet?.raw?.length)return [];
  const tcp=layers.find(l=>l.name==='Transmission Control Protocol'),udp=layers.find(l=>l.name==='User Datagram Protocol');
  const trans=tcp||udp;if(!trans)return [];
  let off=trans.off+trans.len;if(off>=packet.raw.length)return [];
  let size=Math.min(packet.payloadBytes||packet.raw.length-off,packet.raw.length-off),data=packet.raw.subarray(off,off+size),detail=[];
  if(packet.transport==='UDP'&&[53,5353].some(p=>[packet.srcPort,packet.dstPort].includes(p)))detail.push(nc32DnsMessage(data,off));
  if(packet.transport==='TCP'&&[53,5353].some(p=>[packet.srcPort,packet.dstPort].includes(p))&&size>2){const len=read16(data,0);if(len<=size-2)detail.push(nc32DnsMessage(data.subarray(2,2+len),off+2));}
  const tls=nc32TlsHello(data,off);if(tls)detail.push(tls);
  const http=nc32HttpHeaders(data,off);if(http)detail.push(http);
  return detail.filter(Boolean);
}
const nc32BaseInspectLayers=inspectLayers;
inspectLayers=function(packet){
  const layers=nc32BaseInspectLayers(packet),extra=nc32ProtocolLayers(packet,layers);
  if(extra.length){const redundant=new Set(['Domain Name System','Transport Layer Security','Hypertext Transfer Protocol','Payload / Application Data']);return [...layers.filter(x=>!redundant.has(x.name)),...extra];}
  return layers;
};
