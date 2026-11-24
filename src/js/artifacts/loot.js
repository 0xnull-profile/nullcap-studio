'use strict';
/* NullCap Artifact Lab — offline best-effort passive reconstruction.
   Never evaluates recovered HTML, JS or email bodies, and does not decrypt traffic. */
const NC_LOOT_STREAM_LIMIT=10*1024*1024;
const NC_LOOT_TOTAL_LIMIT=55*1024*1024;
const NC_LOOT_ITEM_LIMIT=9*1024*1024;
const NC_LOOT_MAX_ITEMS=320;
const NC_LOOT_MAX_SECONDARY=120;
const NC_UTF8=new TextDecoder('utf-8',{fatal:false});
const NC_LATIN1=new TextDecoder('iso-8859-1');
const NC_CRLFCRLF=new Uint8Array([13,10,13,10]);
function ncRevokeLootURLs(){
  for(const item of state.loot||[])if(item.previewUrl)URL.revokeObjectURL(item.previewUrl);
  for(const url of state.audioURLs||[])URL.revokeObjectURL(url);
  state.audioURLs=[];
}
function ncAsset(entry){
  // Ordinary API responses and repeatable session-cookie notices must not use
  // the whole gallery budget before a useful late-capture finding is parsed.
  const low=(entry.kind==='api'&&!entry.authFinding)||
    (entry.authFinding&&(entry.authCookieOnly||(entry.authDirection==='response'&&!entry.authResponseCredential)));
  state.lootNextId??=0;
  state.lootLowAccepted??=0;
  state.lootNotIndexed??=0;
  if(low&&state.lootLowAccepted>=NC_LOOT_MAX_SECONDARY){state.lootNotIndexed++;return null;}
  if(state.loot.length>=NC_LOOT_MAX_ITEMS){
    if(low){state.lootNotIndexed++;return null;}
    const candidate=state.loot.findIndex(item=>item.preliminarySecondary);
    if(candidate<0){state.lootNotIndexed++;return null;}
    state.loot.splice(candidate,1);
    state.lootLowAccepted=Math.max(0,state.lootLowAccepted-1);
    state.lootNotIndexed++;
  }
  const asset={id:++state.lootNextId,kind:'file',title:'Artefatto',description:'',src:'',dst:'',packetIds:[],rel:0,data:new Uint8Array(),contentType:'application/octet-stream',filename:'artefatto.bin',status:'complete',...entry,preliminarySecondary:low};
  if(!asset.packetIds?.length)return null;
  if(asset.data?.length>NC_LOOT_ITEM_LIMIT)return null;
  if(asset.kind==='image'&&asset.data.length){
    asset.previewUrl=URL.createObjectURL(new Blob([asset.data],{type:asset.contentType}));
  }
  state.loot.push(asset);
  if(low)state.lootLowAccepted++;
  return asset;
}
function ncPayloadInfo(p){
  const b=p.raw,link=p.linkType??1;if(!b||b.length<16)return null;
  let off=0,ether=0;
  if(link===1){if(b.length<14)return null;ether=read16(b,12);off=14;for(let i=0;i<3&&[0x8100,0x88a8,0x9100].includes(ether);i++){if(off+4>b.length)return null;ether=read16(b,off+2);off+=4;}}
  else if([101,228,229].includes(link)){off=0;ether=link===228?0x0800:link===229?0x86dd:(b[0]>>4)===4?0x0800:0x86dd;}
  else if(link===113){if(b.length<16)return null;ether=read16(b,14);off=16;}
  else if(link===276){if(b.length<20)return null;ether=read16(b,0);off=20;}
  else if([0,108].includes(link)){off=4;ether=(b[4]>>4)===4?0x0800:0x86dd;}
  else return null;
  let end=b.length,ipProto;
  if(ether===0x0800){
    if(off+20>b.length||b[off]>>4!==4)return null;
    const ihl=(b[off]&15)*4,frag=read16(b,off+6),total=read16(b,off+2);
    if(ihl<20||off+ihl>b.length||(frag&0x3fff)!==0)return null;
    ipProto=b[off+9];end=Math.min(end,off+total);off+=ihl;
  }else if(ether===0x86dd){
    if(off+40>b.length||b[off]>>4!==6)return null;
    ipProto=b[off+6];end=Math.min(end,off+40+read16(b,off+4));off+=40;
    for(let i=0;i<8;i++){
      if([0,43,60].includes(ipProto)&&off+2<=end){const next=b[off],size=(b[off+1]+1)*8;if(size<8||off+size>end)return null;off+=size;ipProto=next;}
      else if(ipProto===44&&off+8<=end){const fragment=read16(b,off+2);if(fragment&0xfff9)return null;ipProto=b[off];off+=8;}
      else break;
    }
  }else return null;
  if(end> b.length||off>=end)return null;
  if(ipProto===6){
    if(off+20>end)return null;
    const len=(b[off+12]>>4)*4;
    if(len<20||off+len>end)return null;
    return {protocol:'TCP',bytes:b.subarray(off+len,end),seq:read32(b,off+4),flags:b[off+13],packet:p};
  }
  if(ipProto===17){
    if(off+8>end)return null;
    const length=read16(b,off+4),hi=Math.min(end,off+Math.max(8,length));
    return {protocol:'UDP',bytes:b.subarray(off+8,hi),packet:p};
  }
  return null;
}
function ncIndexBytes(hay,needle,from=0){
  outer:for(let i=from;i<=hay.length-needle.length;i++){
    for(let j=0;j<needle.length;j++)if(hay[i+j]!==needle[j])continue outer;
    return i;
  }
  return -1;
}
function ncReadLine(bytes,offset){
  const pos=ncIndexBytes(bytes,new Uint8Array([13,10]),offset);
  if(pos<0)return null;
  return {text:NC_LATIN1.decode(bytes.subarray(offset,pos)),end:pos+2};
}
function ncByteChunks(parts,total){
  let bytes=new Uint8Array(total),off=0;for(const chunk of parts){bytes.set(chunk,off);off+=chunk.length;}
  return bytes;
}
function ncBuildTCPRuns(group){
  let ordered=group.segments.slice().sort((a,b)=>a.seq-b.seq||a.rel-b.rel);
  if(!ordered.length)return [];
  let runs=[],chunks=[],used=[],bytes=0,expected=null,startRel=0;
  function push(){if(!bytes)return;runs.push({bytes:ncByteChunks(chunks,bytes),segments:used,src:group.src,dst:group.dst,srcPort:group.srcPort,dstPort:group.dstPort,rel:startRel});chunks=[];used=[];bytes=0;expected=null;}
  for(const s of ordered){
    if(expected===null){expected=s.seq;startRel=s.rel;}
    // Do not invent bytes for missing TCP segments: split into a new contiguous run.
    if(s.seq>expected){push();expected=s.seq;startRel=s.rel;}
    const overlap=Math.max(0,expected-s.seq),newPart=s.data.subarray(Math.min(s.data.length,overlap));
    if(!newPart.length)continue;
    if(bytes+newPart.length>NC_LOOT_STREAM_LIMIT){push();expected=s.seq+overlap;startRel=s.rel;}
    used.push({start:bytes,end:bytes+newPart.length,packetId:s.id,rel:s.rel});
    chunks.push(newPart);bytes+=newPart.length;expected=s.seq+s.data.length;
  }
  push();return runs;
}
function ncUsedPackets(run,start,end){const seg=run.segments.filter(s=>s.end>start&&s.start<end);return [...new Set(seg.flatMap(s=>s.packetIds?.length?s.packetIds:[s.packetId]))].slice(0,240);}
function ncUsedTime(run,start,end){return run.segments.find(s=>s.end>start&&s.start<end)?.rel??run.rel;}
function ncParseHeaders(text){
  const lines=text.split('\r\n'),startLine=(lines.shift()||'').trim(),headers={};let lastKey='';
  for(const row of lines){
    if(/^\s/.test(row)&&lastKey){headers[lastKey]+=' '+row.trim();continue;}
    const p=row.indexOf(':');if(p<1)continue;const key=row.slice(0,p).toLowerCase().trim();
    headers[key]=row.slice(p+1).trim();lastKey=key;
  }
  return {startLine,headers};
}
function ncUnchunk(body,start){
  const chunks=[];let total=0,offset=start,complete=false;
  for(let i=0;i<20000&&offset<body.length;i++){
    const line=ncReadLine(body,offset);if(!line)return {data:ncByteChunks(chunks,total),end:offset,complete:false};
    const size=parseInt(line.text.split(';')[0].trim(),16);
    if(!Number.isFinite(size)||size<0||size>NC_LOOT_ITEM_LIMIT)return null;
    offset=line.end;
    if(size===0){
      // Last chunk is followed by a CRLF or optional trailers.
      complete=true;
      if(offset+2<=body.length&&body[offset]===13&&body[offset+1]===10)offset+=2;
      else{let trailerEnd=ncIndexBytes(body,NC_CRLFCRLF,offset);if(trailerEnd>=0)offset=trailerEnd+4;}
      break;
    }
    if(offset+size+2>body.length)return {data:ncByteChunks(chunks,total),end:body.length,complete:false};
    chunks.push(body.subarray(offset,offset+size));total+=size;offset+=size+2;
    if(total>NC_LOOT_ITEM_LIMIT)return null;
  }
  return {data:ncByteChunks(chunks,total),end:offset,complete};
}
async function ncDecompressSafe(bytes,encoding){
  if(!['gzip','deflate'].includes(encoding)||typeof DecompressionStream==='undefined')return null;
  try{
    const stream=new Blob([bytes]).stream().pipeThrough(new DecompressionStream(encoding));
    const reader=stream.getReader();const parts=[];let total=0;
    while(true){let {value,done}=await reader.read();if(done)break;total+=value.length;
      if(total>NC_LOOT_ITEM_LIMIT){await reader.cancel();return null;}
      parts.push(value);
    }
    return ncByteChunks(parts,total);
  }catch{return null;}
}
function ncFormatXml(text){
  const xml=text.trim();if(!/^<\?xml\b|^<[a-zA-Z_][\w:.-]*[\s>]/.test(xml))return text.slice(0,30000);
  try{
    const doc=new DOMParser().parseFromString(xml,'application/xml');
    if(doc.querySelector('parsererror'))return text.slice(0,30000);
    let depth=0,out=[];
    const tokens=xml.replace(/>\s*</g,'><').match(/<[^>]*>|[^<]+/g)||[];
    for(const token of tokens.slice(0,5000)){
      const closes=/^<\//.test(token),self=/\/>$/.test(token)||/^<\?|^<!/.test(token);
      if(closes)depth=Math.max(0,depth-1);
      out.push('  '.repeat(Math.min(depth,30))+token.trim());
      if(!closes&&!self&&/^<[a-zA-Z_]/.test(token))depth++;
    }
    return out.join('\n').slice(0,30000);
  }catch{return text.slice(0,30000);}
}
function ncFileName(text,fallback){
  const encoded=text.match(/filename\*\s*=\s*(?:UTF-8''|[^;]*'')([^;]+)/i);
  let name='';if(encoded){try{name=decodeURIComponent(encoded[1].replace(/^"|"$/g,'').trim());}catch{}}
  if(!name){const match=text.match(/filename\s*=\s*(?:"([^"]+)"|([^;]+))/i);name=match?.[1]||match?.[2]||fallback;}
  return String(name||fallback).replace(/[\\/\x00-\x1f\x7f<>:"|?*]/g,'_').trim().slice(0,150)||fallback;
}
function ncSniffMime(data,mime){
  mime=(mime||'').split(';')[0].trim().toLowerCase();
  const is=(sig)=>data.length>=sig.length&&sig.every((n,i)=>data[i]===n);
  if(is([137,80,78,71,13,10,26,10]))return 'image/png';
  if(is([0xff,0xd8,0xff]))return 'image/jpeg';
  if(is([71,73,70,56]))return 'image/gif';
  if(is([82,73,70,70])&&data.length>12&&String.fromCharCode(...data.slice(8,12))==='WEBP')return 'image/webp';
  if(is([37,80,68,70,45]))return 'application/pdf';
  if(is([0x50,0x4b,0x03,0x04]))return 'application/zip';
  // Never put unverified HTML/SVG inside an image preview, even if the server
  // advertised an image Content-Type.
  if(/^image\//.test(mime))return 'application/octet-stream';
  return mime||'application/octet-stream';
}
/* 3.1.2: HTTP auth extraction retains values exclusively in volatile browser state.
   The request/response parser and display are kept in this module; field scanning
   and conservative login-outcome correlation live in v312-auth.js. */
const NC_HTTP_AUTH_MAX_BODY=256*1024;
function ncHttpSensitiveField(name){
  const key=String(name||'').replace(/\[([^\]]+)\]/g,'.$1').replace(/([a-z])([A-Z])/g,'$1_$2').toLowerCase();
  const bits=key.split(/[.\-_/]+/).filter(Boolean);
  if(!bits.length)return false;
  const exact=['password','passwd','pwd','pass','passcode','passphrase','jpassword','j_password','client_secret','api_key','apikey','access_token','refresh_token','auth_token','authentication_token','id_token','otp','totp'];
  const compact=key.replace(/[^a-z0-9]/g,'');
  if(exact.includes(key)||exact.includes(compact))return true;
  if(bits.some(b=>['password','passwd','pwd','pass','passcode','passphrase'].includes(b)))
    return !bits.some(b=>['hint','policy','strength','length','salt','algorithm','reset','enabled'].includes(b));
  return bits.slice(-2).join('_')==='client_secret'||bits.slice(-2).join('_')==='access_token'||bits.slice(-2).join('_')==='api_key';
}
function ncHttpSafeTarget(raw){
  let path=String(raw||'/').split(/[?#]/)[0];
  // An absolute HTTP URI may contain userinfo. Never display its authority.
  path=path.replace(/^https?:\/\/[^/]+/i,'');
  return (path||'/').replace(/[\x00-\x1f\x7f]/g,'').slice(0,100);
}
async function ncHttpFromRun(run){
  const data=run.bytes;let offset=0,parsed=0;
  const requestRE=/^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|TRACE|CONNECT)\s+\S+\s+HTTP\/1\.[01]$/i;
  const responseRE=/^HTTP\/1\.[01]\s+\d{3}\b/i;
  while(offset<data.length&&parsed<1200){
    const headerEnd=ncIndexBytes(data,NC_CRLFCRLF,offset);if(headerEnd<0)break;
    if(headerEnd-offset>32768){offset=headerEnd+4;continue;}
    const head=ncParseHeaders(NC_LATIN1.decode(data.subarray(offset,headerEnd)));
    if(!requestRE.test(head.startLine)&&!responseRE.test(head.startLine)){
      // Find next HTTP start line on a CRLF boundary, never interpret arbitrary binary as headers.
      const next=ncIndexBytes(data,new Uint8Array([13,10]),offset);
      if(next<0||next>offset+32768)break;
      offset=next+2;continue;
    }
    parsed++;
    const start=offset,bodyStart=headerEnd+4,h=head.headers,declared=parseInt(h['content-length']||'',10);
    let body=new Uint8Array(0),bodyEnd=bodyStart,complete=true;
    const transfer=String(h['transfer-encoding']||'').toLowerCase();
    if(transfer.includes('chunked')){
      const chunked=ncUnchunk(data,bodyStart);if(!chunked)break;
      body=chunked.data;bodyEnd=chunked.end;complete=chunked.complete;
    }else if(Number.isFinite(declared)&&declared>=0){
      if(declared>NC_LOOT_ITEM_LIMIT){offset=bodyStart+declared;if(offset>data.length)break;continue;}
      bodyEnd=Math.min(data.length,bodyStart+declared);body=data.subarray(bodyStart,bodyEnd);complete=body.length===declared;
    }else if(responseRE.test(head.startLine)&&!/^HTTP\/1\.[01]\s+(?:1\d\d|204|304)/.test(head.startLine)){
      body=data.subarray(bodyStart,Math.min(data.length,bodyStart+NC_LOOT_ITEM_LIMIT));bodyEnd=data.length;complete=false;
    }
    if(bodyEnd<=start){offset=headerEnd+4;continue;}
    let encoding=String(h['content-encoding']||'').toLowerCase(),decoded=body;
    if(encoding==='gzip'||encoding==='deflate'){const plain=await ncDecompressSafe(body,encoding);if(plain)decoded=plain;else decoded=null;}
    const mime=ncSniffMime(decoded||body,h['content-type']);
    const fallback='http-'+(state.loot.length+1);
    const name=ncFileName(h['content-disposition']||'',fallback+(mime==='image/png'?'.png':mime==='image/jpeg'?'.jpg':mime==='application/pdf'?'.pdf':'.bin'));
    const isRequest=requestRE.test(head.startLine),status=complete?'complete':'partial';
    const packetIds=ncUsedPackets(run,start,Math.min(data.length,Math.max(bodyEnd,headerEnd+4)));
    const base={src:run.src,dst:run.dst,rel:ncUsedTime(run,start,bodyEnd),packetIds,status,metadata:head.startLine,filename:name,
      reassemblyQuality:run.reassemblyQuality||'unknown',reassemblyWarnings:run.reassemblyWarnings||[]};
    // Version 3.1.2: retain sensitive values exclusively in the in-memory gallery,
    // and mark the exact TCP payload segments that carried the relevant field.
    const rawHeader=NC_LATIN1.decode(data.subarray(start,headerEnd));
    const authFinding=nc312ExtractAuthentication(head,rawHeader,decoded||new Uint8Array(),
      {response:!isRequest,compressed:decoded!==body});
    let asset=null;
    if(authFinding){
      const sensitiveIds=nc312ExposurePackets(run,start,bodyEnd,authFinding);
      asset=ncAsset({...base,kind:'api',authFinding:true,
        authIsLogin:authFinding.isLogin,authDirection:isRequest?'request':'response',
        authResponseCredential:!isRequest&&authFinding.hits.some(h=>h.kind==='credential'),
        authOutcome:isRequest?'unknown':'issued',authOutcomeReason:'',
        authPacketIds:sensitiveIds,authCookieOnly:isRequest&&authFinding.hits.length>0&&authFinding.hits.every(h=>h.where==='Cookie HTTP'),
        title:authFinding.title+(authFinding.isLogin&&authFinding.identities?.length?' · '+String(authFinding.identities[0].value).slice(0,60):''),
        description:'Credenziali o token rilevati nel traffico HTTP in chiaro · valori visibili localmente',
        metadata:authFinding.metadata,previewText:authFinding.previewText,
        contentType:'application/vnd.nullcap.auth-finding',filename:'',data:new Uint8Array()});
    }
    // Retain HTTP message order in volatile memory for conservative request/response
    // correlation. 1xx responses do not close a request. Unmatched 200 is NOT success.
    let emittedEvent=null;
    if(state.httpEvents.length<NC312_EVENT_LIMIT){
      const statusCode=isRequest?null:Number((head.startLine.match(/^HTTP\/1\.[01]\s+(\d{3})/)||[])[1]);
      const tokenIssued=!isRequest&&Boolean(authFinding?.hits.some(x=>x.kind==='token'));
      emittedEvent={type:isRequest?'request':'response',flowKey:flowKey({
        src:run.src,dst:run.dst,srcPort:run.srcPort,dstPort:run.dstPort,transport:'TCP'}),
        rel:base.rel,order:state.httpEvents.length,assetId:asset?.id||null,
        isLogin:authFinding?.isLogin||false,route:isRequest?ncHttpSafeTarget(head.startLine.split(/\s+/)[1]):'',
        method:isRequest?head.startLine.split(/\s+/)[0].toUpperCase():'',
        src:run.src,dst:run.dst,srcPort:run.srcPort,dstPort:run.dstPort,
        host:isRequest?String(h.host||''):'',
        statusCode,headers:h,tokenIssued,
        authHits:authFinding?.hits||[],
        authIdentities:authFinding?.identities||[], // already observed, volatile only (A21 inspector)
        bodyLength:decoded?.length||0,bodyComplete:complete,
        bodyText:!isRequest&&decoded&&decoded.length<=NC_HTTP_AUTH_MAX_BODY?NC_UTF8.decode(decoded.subarray(0,12000)):'',
        packetIds};
      state.httpEvents.push(emittedEvent);
    }
    // Avoid duplicate downloadable JSON/form artifacts for a secret-bearing message.
    if(decoded&&decoded.length&&!authFinding){
      if(['image/png','image/jpeg','image/gif','image/webp'].includes(mime)){
        ncAsset({...base,kind:'image',title:name.startsWith('http-')?'Immagine HTTP · '+run.src:name,
          description:head.startLine,contentType:mime,data:decoded});
      }else if(!authFinding&&(/json|xml/.test(mime)||/\+json|\+xml/.test(h['content-type']||''))){
        let formatted=NC_UTF8.decode(decoded.subarray(0,NC_LOOT_ITEM_LIMIT));let valid=true;
        if(/json/.test(mime)){try{formatted=JSON.stringify(JSON.parse(formatted),null,2);}catch{valid=false;}}
        else formatted=ncFormatXml(formatted);
        const methodOrStatus=head.startLine.split(/\s+/).slice(0,2).join(' ');
        const ordinary=ncAsset({...base,kind:'api',title:methodOrStatus+' · '+run.src,
          description:(h['content-type']||mime)+(valid?'':' · JSON non valido'),
          contentType:mime,data:decoded,previewText:formatted.slice(0,45000),
          filename:name.startsWith('http-')?fallback+(/json/.test(mime)?'.json':'.xml'):name});
        if(emittedEvent&&ordinary)emittedEvent.assetId=ordinary.id;
      }else if(h['content-disposition']?.toLowerCase().includes('attachment')||['application/pdf','application/zip','application/octet-stream'].includes(mime)){
        ncAsset({...base,kind:'file',title:name,description:head.startLine,contentType:mime,data:decoded,
          previewText:mime.startsWith('text/')?NC_UTF8.decode(decoded.slice(0,2000)):''});
      }
    }
    if(bodyEnd<=offset)break;
    offset=bodyEnd;
    if(!complete)break;
  }
}
function ncEmailFromRun(run){
  if(![25,587,2525,110,143].includes(run.srcPort)&&![25,587,2525,110,143].includes(run.dstPort))return;
  if(run.bytes.length>3*1024*1024)return;
  let text=NC_LATIN1.decode(run.bytes),found=[],re=/(?:^|\r\n)DATA\r\n([\s\S]*?)\r\n\.\r\n/g,m;
  while((m=re.exec(text))&&found.length<20)found.push({text:m[1].replace(/\r\n\.\./g,'\r\n.'),offset:m.index,length:m[0].length,complete:true});
  // POP3 / IMAP may return a raw RFC822 message without the SMTP DATA command.
  if(!found.length&&/^(?:\+OK|\* \d+ FETCH)/i.test(text)&&/\r\n(?:From|To|Subject):/i.test(text)){
    const at=text.search(/(?:^|\r\n)(From|Date|Subject):/i);
    if(at>=0)found.push({text:text.slice(at+((text[at]==='\r')?2:0),Math.min(text.length,at+100000)),offset:at,length:text.length-at,complete:false});
  }
  for(const msg of found){
    const headers=msg.text.split(/\r\n\r\n/)[0],get=name=>(headers.match(new RegExp('(?:^|\\r\\n)'+name+':\\s*([^\\r\\n]+)','i'))||[])[1]||'—';
    const subject=get('Subject'),from=get('From'),to=get('To');
    let data=new TextEncoder().encode(msg.text.replace(/\r\n/g,'\r\n'));
    ncAsset({kind:'email',title:subject==='—'?'Messaggio email':subject,description:'Da '+from+' · A '+to,
      metadata:'Messaggio RFC822 in chiaro',src:run.src,dst:run.dst,rel:run.rel,
      packetIds:ncUsedPackets(run,msg.offset,msg.offset+msg.length),status:msg.complete?'complete':'partial',data,
      reassemblyQuality:run.reassemblyQuality||'unknown',reassemblyWarnings:run.reassemblyWarnings||[],
      contentType:'message/rfc822',filename:'email-'+String(state.loot.length+1).padStart(3,'0')+'.eml',
      previewText:msg.text.slice(0,40000),emailInfo:{from,to,subject}});
  }
}
function ncRtpParse(bytes){
  if(bytes.length<24||(bytes[0]>>6)!==2)return null;
  const pt=bytes[1]&0x7f;if(pt!==0&&pt!==8)return null;
  const cs=bytes[0]&15,hasExt=!!(bytes[0]&0x10),padded=!!(bytes[0]&0x20);
  let offset=12+4*cs;if(offset>=bytes.length)return null;
  if(hasExt){if(offset+4>bytes.length)return null;offset+=4+read16(bytes,offset+2)*4;}
  if(offset>=bytes.length)return null;
  let end=bytes.length;if(padded){end-=bytes[bytes.length-1];if(end<=offset)return null;}
  return {pt,seq:read16(bytes,2),timestamp:read32(bytes,4),ssrc:read32(bytes,8),data:bytes.subarray(offset,end)};
}
function ncMuLaw(b){const u=(~b)&255,sign=u&0x80,exp=(u>>4)&7,m=u&15;
 let sample=(((m<<3)+0x84)<<exp)-0x84;return sign?-sample:sample;
}
function ncALaw(b){const a=b^0x55,sign=a&0x80,exp=(a&0x70)>>4,m=a&15;
 let sample=exp?((m<<4)+0x108)<<(exp-1):(m<<4)+8;return sign?sample:-sample;
}
function ncEncodeWav(samples){
  let b=new Uint8Array(44+samples.length*2),d=new DataView(b.buffer);
  const s=(at,x)=>{for(let i=0;i<x.length;i++)b[at+i]=x.charCodeAt(i);};
  s(0,'RIFF');d.setUint32(4,b.length-8,true);s(8,'WAVE');s(12,'fmt ');d.setUint32(16,16,true);
  d.setUint16(20,1,true);d.setUint16(22,1,true);d.setUint32(24,8000,true);d.setUint32(28,16000,true);
  d.setUint16(32,2,true);d.setUint16(34,16,true);s(36,'data');d.setUint32(40,samples.length*2,true);
  for(let i=0;i<samples.length;i++)d.setInt16(44+i*2,Math.max(-32768,Math.min(32767,samples[i])),true);
  return b;
}
function ncRtpGroupsToAssets(groups){
  for(const group of groups.values()){
    if(group.frames.length<6)continue;
    const frames=group.frames.sort((a,b)=>a.timestamp-b.timestamp||a.seq-b.seq);
    // A valid RTP stream must have progressing timestamps. Avoid accidentally decoding random UDP.
    if(frames.length<6||frames.filter((f,i)=>i>0&&f.timestamp>frames[i-1].timestamp).length<4)continue;
    let first=frames[0],expected=first.timestamp,samples=[],used=new Set(),limit=8000*120,hasGaps=false;
    for(const frame of frames){
      if(samples.length>=limit)break;
      const missing=frame.timestamp-expected;
      if(missing>0){hasGaps=true;if(missing<=8000)samples.push(...new Array(Math.min(missing,8000)).fill(0));}
      if(missing<-(frame.data.length/2))continue;
      const trim=Math.max(0,-missing);
      for(let i=trim;i<frame.data.length&&samples.length<limit;i++)samples.push(group.pt===0?ncMuLaw(frame.data[i]):ncALaw(frame.data[i]));
      expected=frame.timestamp+frame.data.length;used.add(frame.id);
    }
    if(samples.length<160*5)continue;
    const sampleArray=new Int16Array(samples),data=ncEncodeWav(sampleArray);
    ncAsset({kind:'audio',title:`VoIP · ${group.pt===0?'G.711 μ-law':'G.711 A-law'}`,
      description:`Flusso RTP ${group.src}:${group.srcPort} → ${group.dst}:${group.dstPort}`,
      metadata:`SSRC 0x${group.ssrc.toString(16)} · ${Math.round(samples.length/8000*10)/10} s · 8000 Hz`,
      src:group.src,dst:group.dst,rel:first.rel,packetIds:[...used].slice(0,240),
      status:hasGaps?'partial':'complete',contentType:'audio/wav',filename:`rtp-${group.ssrc.toString(16)}.wav`,data,
      audioDuration:samples.length/8000});
  }
}
async function ncExtractLoot(generation){
  // Yield to paint and prevent blocking the initial dashboard update.
  await new Promise(resolve=>setTimeout(resolve,25));
  if(generation!==state.captureGeneration)return;
  try{
    const tcp=new Map(),rtp=new Map();let total=0,skipped=0;
    for(const p of state.packets){
      const info=ncPayloadInfo(p);if(!info||!info.bytes.length)continue;
      if(info.protocol==='TCP'){
        if(total+info.bytes.length>NC_LOOT_TOTAL_LIMIT){skipped++;continue;}
        const key=[p.src,p.srcPort,p.dst,p.dstPort].join('\x1f');
        let group=tcp.get(key);
        if(!group){if(tcp.size>2800)continue;group={src:p.src,dst:p.dst,srcPort:p.srcPort,dstPort:p.dstPort,segments:[]};tcp.set(key,group);}
        group.segments.push({seq:info.seq,data:info.bytes,id:p.id,rel:p.rel});total+=info.bytes.length;
      }else if(info.protocol==='UDP'){
        const frame=ncRtpParse(info.bytes);
        if(!frame)continue;
        const key=[p.src,p.srcPort,p.dst,p.dstPort,frame.ssrc,frame.pt].join('\x1f');
        let group=rtp.get(key);
        if(!group){group={src:p.src,dst:p.dst,srcPort:p.srcPort,dstPort:p.dstPort,ssrc:frame.ssrc,pt:frame.pt,frames:[]};rtp.set(key,group);}
        group.frames.push({...frame,id:p.id,rel:p.rel});
      }
    }
    let processed=0;
    let nc16Indexed=null;
    if(typeof nc16BuildTCPGroups==='function'){
      try{nc16Indexed=nc16BuildTCPGroups(state.packets);state.lootTCPMode=nc16Indexed?'a12':'bounded-fallback';}
      catch(err){console.warn('A16 reassembly limited:',err);state.lootTCPMode='bounded-fallback';}
    }
    for(const group of (nc16Indexed||tcp.values())){
      if(generation!==state.captureGeneration)return;
      const runs=nc16Indexed?group.runs:ncBuildTCPRuns(group);
      for(const run of runs){
        if(!run.bytes.length)continue;
        if([25,587,2525,110,143].some(x=>x===group.srcPort||x===group.dstPort))ncEmailFromRun(run);
        // Also recognize HTTP/1.x on non-standard ports (e.g. 5000, 8088).
        const lead=NC_LATIN1.decode(run.bytes.subarray(0,Math.min(128,run.bytes.length)));
        if([80,8080,8000,8888,8081,3000].some(x=>x===group.srcPort||x===group.dstPort)||
          /^(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS|TRACE|CONNECT)\s|^HTTP\/1\.[01]\s/i.test(lead)){
          await ncHttpFromRun(run);
        }
      }
      if(++processed%80===0)await new Promise(resolve=>setTimeout(resolve,0));
    }
    if(generation!==state.captureGeneration)return;
    ncRtpGroupsToAssets(rtp);
    nc313CorrelateHTTP();
    state.lootStatus=(skipped||state.lootNotIndexed||state.lootIPIncomplete||state.lootTCPMode==='bounded-fallback')?'limited':'done';
    ncRenderLoot();renderPacketTable();renderPacketInspector();ncRunDashboard();
  }catch(err){state.lootStatus='error';console.warn('NullCap artefacts:',err);ncRenderLoot();}
}

/* -------- Artifact Lab gallery, inspectable provenance and safe exports -------- */
function ncKindLabel(kind){return ({image:'IMMAGINE',file:'FILE',email:'EMAIL',api:'API / DATI',audio:'AUDIO VoIP'})[kind]||kind.toUpperCase();}
function ncKindIcon(kind){return ncIcon(({image:'image',file:'file-text',email:'mail',api:'braces',audio:'audio'})[kind]||'package');}
function nc312OutcomeLabel(a){
  if(a.authDirection==='response')return a.authResponseCredential?'CREDENZIALI ESPOSTE':'TOKEN OSSERVATO';
  if(!a.authIsLogin&&!a.authEvidence)return 'AUTENTICAZIONE';
  return nc313OutcomeLabel(a);
}
function nc312OutcomeClass(a){
  if(a.authDirection==='response')return a.authResponseCredential?'nc312-failed':'nc312-issued';
  if(!a.authIsLogin&&!a.authEvidence)return 'nc312-neutral';
  return 'nc312-'+(a.authOutcome||'unknown');
}
function ncRenderLoot(){
  const assets=state.loot||[];
  const num=kind=>assets.filter(a=>a.kind===kind&&!a.secondary).length;
  $('lootTotal').textContent=formatN(assets.filter(a=>!a.secondary).length);
  $('lootImageCount').textContent=formatN(num('image'));
  $('lootFileCount').textContent=formatN(num('file'));
  $('lootEmailCount').textContent=formatN(num('email'));
  $('lootAPIcount').textContent=formatN(num('api'));
  $('lootAudioCount').textContent=formatN(num('audio'));
  if($('navLootCount'))$('navLootCount').textContent=assets.length?formatN(assets.filter(a=>!a.secondary).length):'05';
  $('lootAllTabCount').textContent=formatN(assets.filter(a=>!a.secondary).length);
  $('lootScanStatus').innerHTML=`<i class="status-light"></i> ${state.lootStatus==='scanning'?'RICOSTRUZIONE IN CORSO':state.lootStatus==='limited'?'PARZIALE · LIMITI DI ANALISI':state.lootStatus==='error'?'SCAN NON COMPLETO':state.lootStatus==='idle'?'NESSUNA ACQUISIZIONE':'ANALISI COMPLETATA'}`;
  $('lootTabs').querySelectorAll('[data-loot-kind]').forEach(b=>b.classList.toggle('is-active',b.dataset.lootKind===state.lootKind));
  const available=assets.filter(a=>(typeof nc16KindMatch==='function'?nc16KindMatch(a,state.lootKind):(state.lootKind==='ALL'||a.kind===state.lootKind)));
  const searchActive=Boolean(state.lootSearch);
  let filtered=available.filter(a=>(state.lootShowSecondary||searchActive||!a.secondary)&&
    (!searchActive||[a.title,a.src,a.dst,a.filename,a.contentType,a.description].some(s=>String(s||'').toLowerCase().includes(state.lootSearch))));
  if(typeof nc16FilterSort==='function')filtered=nc16FilterSort(filtered);
  const hidden=available.filter(a=>a.secondary).length;
  if($('lootSecondaryCount'))$('lootSecondaryCount').textContent=formatN(hidden);
  if($('lootShowSecondary'))$('lootShowSecondary').checked=Boolean(state.lootShowSecondary);
  $('lootTotal').textContent=formatN(assets.length-hidden);
  $('lootAllTabCount').textContent=formatN(assets.length-hidden);
  $('lootListCount').textContent=`${formatN(filtered.length)} evidenze visibili · ${formatN(hidden)} elementi secondari disponibili${state.lootNotIndexed?' · '+formatN(state.lootNotIndexed)+' segnali secondari non indicizzati (limite)':''}${searchActive?' · ricerca su tutti i rilevamenti':''}`;
  $('lootGallery').innerHTML=filtered.length?filtered.map(a=>{
    const name=escapeHtml(a.title),kind=escapeHtml(ncKindLabel(a.kind)),meta=`${escapeHtml(a.src)} → ${escapeHtml(a.dst)}`;
    const picture=a.kind==='image'&&a.previewUrl?`<img src="${escapeHtml(a.previewUrl)}" alt="Anteprima ${name}" loading="lazy">`:`<div class="file-emoji" aria-hidden="true">${ncKindIcon(a.kind)}</div>`;
    const outcome=a.authFinding?nc312OutcomeLabel(a):'';
    const sourceQuality=(typeof nc16Quality==='function'?nc16Quality(a):a.status==='partial'?'partial':'complete');
    return `<button type="button" class="loot-card ${state.selectedLoot===a.id?'is-selected':''}" data-asset="${a.id}"> <div class="loot-thumb">${picture}<span class="loot-kind-tag">${kind}</span></div><div class="loot-card-body"><strong title="${name}">${name}</strong><small title="${meta}">${meta}</small><div class="loot-card-bottom"><span>${a.authFinding?'DATI IN CHIARO':formatBytes(a.data?.length||0)}${a.repeatCount>1?' · '+formatN(a.repeatCount)+' osservazioni':''}</span><span class="loot-status ${a.authFinding?'nc312-outcome '+nc312OutcomeClass(a):sourceQuality==='ambiguous'?'nc16-ambiguous':sourceQuality==='partial'?'partial':''}">${a.authFinding?outcome:(sourceQuality==='ambiguous'?'AMBIGUO':sourceQuality==='partial'?'PARZIALE':'COMPLETO')}</span></div></div></button>`;
  }).join(''):`<div class="loot-empty"><svg aria-hidden="true" focusable="false"><use href="#i-vault"/></svg><strong>${state.lootStatus==='scanning'?'Ricostruzione in corso…':state.lootStatus==='idle'?'Nessuna acquisizione caricata':'Nessun contenuto disponibile'}</strong><span>${state.lootStatus==='scanning'?'I flussi sono analizzati localmente.':state.lootStatus==='idle'?'Importa un file PCAP o PCAPNG per avviare la ricostruzione degli artefatti.':'Nessun artefatto corrisponde ai filtri oppure il traffico è cifrato, incompleto o usa un formato non ancora supportato.'}</span></div>`;
  $('lootGallery').querySelectorAll('[data-asset]').forEach(b=>b.onclick=()=>{
    state.selectedLoot=Number(b.dataset.asset);ncRenderLoot();ncRenderLootDetail();
  });
  ncRenderLootDetail();
}
function ncRenderLootDetail(){
  const asset=state.loot.find(a=>a.id===state.selectedLoot),target=$('lootDetail');
  if(!asset){target.innerHTML='<div class="loot-blank"><svg aria-hidden="true" focusable="false"><use href="#i-vault"/></svg><b>Seleziona un artefatto</b><span>Visualizzerai anteprima, formato, sorgente, destinazione e riferimenti ai pacchetti che lo compongono.</span></div>';return;}
  const hasRaw=!!(asset.data&&asset.data.length);
  const time=Number.isFinite(asset.rel)?formatTime(asset.rel,true):'N/D';
  target.innerHTML=`<div class="loot-detail-header"><span class="kind">${escapeHtml(ncKindLabel(asset.kind))}</span><span class="loot-status ${asset.authFinding?'nc312-outcome '+nc312OutcomeClass(asset):asset.status==='partial'?'partial':''}">${asset.authFinding?nc312OutcomeLabel(asset):(asset.status==='partial'?'PARZIALE':'COMPLETO')}</span></div>
    <h3>${escapeHtml(asset.title)}</h3><p>${escapeHtml(asset.description||'Evidenza ricostruita dai pacchetti')}</p>${asset.authFinding?`<div class="nc312-secret-warning">${ncIcon("alert")} VALORI SENSIBILI IN CHIARO · Solo questa sessione locale. Attenzione a screenshot e condivisioni schermo.</div>`:''}
    <div class="loot-info-list">
      <div class="loot-info-row"><span>Tipo MIME</span><strong>${escapeHtml(asset.contentType)}</strong></div>
      <div class="loot-info-row"><span>${asset.authFinding?'Valori sensibili':'Dimensioni'}</span><strong>${asset.authFinding?'Visibili · solo memoria volatile':formatBytes(asset.data.length)}</strong></div>
      ${asset.authFinding?`<div class="loot-info-row"><span>Esito autenticazione</span><strong>${escapeHtml(nc312OutcomeLabel(asset))}</strong></div>`:''}
      <div class="loot-info-row"><span>Primo evento</span><strong>${time}</strong></div>
      <div class="loot-info-row"><span>Sorgente</span><strong>${escapeHtml(asset.src)}</strong></div>
      <div class="loot-info-row"><span>Destinazione</span><strong>${escapeHtml(asset.dst)}</strong></div>
      <div class="loot-info-row"><span>Pacchetti associati</span><strong>${formatN(asset.packetIds.length)} · #${asset.packetIds[0]}</strong></div>
      <div class="loot-info-row"><span>Contesto</span><strong>${escapeHtml(asset.metadata||'—')}</strong></div>
      ${asset.httpResponseStatus?`<div class="loot-info-row"><span>Risposta HTTP</span><strong>${asset.httpResponseStatus} · frame ${escapeHtml((asset.httpResponseFrameIds||[]).map(x=>'#'+x).join(', '))}</strong></div>`:''}
    </div>${asset.authEvidence?`<div class="nc313-evidence-panel"><strong>SEQUENZA DI AUTENTICAZIONE · ${escapeHtml(asset.authConfidence||'')}</strong><p>Analisi passiva: non verifica le credenziali sul servizio.</p>${asset.authEvidence.traces.map(t=>`<button type="button" class="nc313-evidence-link" data-http-frame="${t.frameId||''}" ${t.frameId?'':'disabled'}><b>#${t.frameId||'?'} · ${escapeHtml(t.request)}</b><span>${escapeHtml(t.status?'HTTP '+t.status:'risposta N/D')} · ${escapeHtml(t.why)}</span></button>`).join('')}</div>`:''}
    ${asset.secondary?`<p class="nc313-secondary-note">Elemento secondario: ${escapeHtml(asset.secondaryReason||'')}</p>`:''}
    <div id="lootPreview" class="loot-preview"></div>
    <div class="loot-action-row"><button id="lootDownload" ${hasRaw?'':'disabled'}><svg aria-hidden="true" focusable="false"><use href="#i-download"/></svg>Scarica l'evidenza</button><button id="lootInspectPacket" class="secondary-action"><svg aria-hidden="true" focusable="false"><use href="#i-packets"/></svg>Esamina il pacchetto sorgente #${asset.packetIds[0]}</button></div>`;
  const preview=$('lootPreview');
  if(asset.kind==='image'&&asset.previewUrl){const img=document.createElement('img');img.src=asset.previewUrl;img.alt='Anteprima locale di '+asset.title;preview.appendChild(img);}
  else if(asset.kind==='audio'){
    if(!asset.audioUrl){asset.audioUrl=URL.createObjectURL(new Blob([asset.data],{type:'audio/wav'}));state.audioURLs.push(asset.audioUrl);}
    let audio=document.createElement('audio');audio.controls=true;audio.preload='none';audio.src=asset.audioUrl;preview.appendChild(audio);
    let p=document.createElement('p');p.textContent='Audio G.711 ricodificato in WAV PCM, 8 kHz, mono. Eventuali perdite nella cattura possono interrompere il flusso.';p.style.padding='0 12px 12px';preview.appendChild(p);
  }else if(asset.kind==='api'||asset.kind==='email'||asset.previewText){
    const pre=document.createElement('pre');pre.textContent=String(asset.previewText||'Contenuto non disponibile').slice(0,45000);preview.appendChild(pre);
  }else{
    let pre=document.createElement('pre');pre.textContent='Anteprima non disponibile per questo formato. Puoi scaricare i byte ricostruiti e analizzare i frame di origine.';preview.appendChild(pre);
  }
  $('lootDownload').onclick=()=>ncDownloadLoot(asset);
  $('lootInspectPacket').onclick=()=>openPacketById(asset.packetIds[0]);
  target.querySelectorAll('[data-http-frame]').forEach(btn=>btn.onclick=()=>openPacketById(Number(btn.dataset.httpFrame)));
}
function ncDownloadLoot(asset){
  if(!asset?.data?.length)return;
  const blob=new Blob([asset.data],{type:asset.contentType||'application/octet-stream'});
  const url=URL.createObjectURL(blob),a=document.createElement('a');a.href=url;
  a.download=ncFileName('',asset.filename||'nullcap-artifact-'+asset.id+'.bin');
  document.body.appendChild(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),10000);
  notify('Evidenza esportata',asset.filename+' · '+formatBytes(asset.data.length));
}

/* -------- Rich synthetic capture to demonstrate the extraction workflow -------- */
function ncConcat(...arrays){let size=arrays.reduce((n,b)=>n+b.length,0),out=new Uint8Array(size),i=0;for(const a of arrays){out.set(a,i);i+=a.length;}return out;}
function ncText(s){return new TextEncoder().encode(s);}
function ncDemoPacket({src,dst,srcPort,dstPort,protocol='TCP',seq=0,body=new Uint8Array(0),ts,info=''}){
  const udp=protocol==='UDP',off=14+20+ (udp?8:20);
  const bytes=new Uint8Array(off+body.length);bytes.set([2,20,24,16,19,60,2,10,16,80,40,15],0);
  writeU16(bytes,12,0x0800);bytes[14]=0x45;writeU16(bytes,16,bytes.length-14);writeU16(bytes,18,((ts*1000)>>>0)&0xffff);writeU16(bytes,20,0x4000);
  bytes[22]=64;bytes[23]=udp?17:6;bytes.set(ipBytes(src),26);bytes.set(ipBytes(dst),30);
  writeU16(bytes,34,srcPort);writeU16(bytes,36,dstPort);
  if(udp){writeU16(bytes,38,body.length+8);}else{writeU32(bytes,38,seq>>>0);bytes[46]=0x50;bytes[47]=0x18;writeU16(bytes,48,8192);}
  bytes.set(body,off);const decoded=decodeFrame(bytes,1);
  if(!decoded)return null;
  return {...decoded,raw:bytes,linkType:1,ts,length:bytes.length,capturedLen:bytes.length,source:'Scenario dimostrativo',info:info||decoded.info};
}
function ncDemoSend(target,base,src,dst,sp,dp,stamp,parts,label){
  let seq=170000+(sp*11)%100000;
  for(const part of parts){
    const bytes=part instanceof Uint8Array?part:ncText(String(part));
    for(let offset=0;offset<bytes.length;offset+=600){
      const chunk=bytes.subarray(offset,Math.min(bytes.length,offset+600));
      target.push(ncDemoPacket({src,dst,srcPort:sp,dstPort:dp,seq,body:chunk,ts:base+stamp,info:label}));
      seq+=chunk.length;stamp+=.008;
    }
  }
}
function ncDemoPNG(){
  let canvas=document.createElement('canvas');canvas.width=320;canvas.height=182;
  let ctx=canvas.getContext('2d');const gr=ctx.createLinearGradient(0,0,320,182);
  gr.addColorStop(0,'#112c44');gr.addColorStop(.55,'#14404b');gr.addColorStop(1,'#33234e');
  ctx.fillStyle=gr;ctx.fillRect(0,0,320,182);
  let pts=[[67,95],[125,64],[166,119],[237,74],[277,128],[109,148],[218,143]];
  ctx.lineWidth=2;ctx.strokeStyle='rgba(131,206,235,.39)';for(let i=1;i<pts.length;i++){ctx.beginPath();ctx.moveTo(...pts[0]);ctx.lineTo(...pts[i]);ctx.stroke();}
  for(let i=0;i<pts.length;i++){let p=pts[i];ctx.beginPath();ctx.arc(p[0],p[1],i===0?12:7,0,Math.PI*2);ctx.strokeStyle=i%2?'#b49dff':'#7aefe0';ctx.lineWidth=2.5;ctx.stroke();ctx.fillStyle='#d4fff6';ctx.beginPath();ctx.arc(p[0],p[1],2.7,0,Math.PI*2);ctx.fill();}
  ctx.fillStyle='#dcf5ff';ctx.font='700 20px system-ui';ctx.fillText('NullCap / LAB',21,35);ctx.font='10px monospace';ctx.fillStyle='#a2c6d8';ctx.fillText('CAPTURE ASSET · SYNTHETIC',21,50);
  const encoded=canvas.toDataURL('image/png').split(',')[1],bin=atob(encoded);
  return Uint8Array.from(bin,c=>c.charCodeAt(0));
}
function ncULawEncode(s){
  const BIAS=0x84,CLIP=32635,sign=s<0?0x80:0;let sample=Math.min(CLIP,Math.abs(s))+BIAS;
  let exponent=7;for(let mask=0x4000;exponent>0&&!(sample&mask);exponent--,mask>>=1){}
  const mantissa=(sample>>(exponent+3))&0x0f;
  return (~(sign|(exponent<<4)|mantissa))&255;
}
function ncEnrichDemo(packets){
  const all=packets.slice();const base=all[0]?.ts||1731000000;
  const local='192.168.1.12',api='34.120.5.29',cdn='104.18.32.47',nas='192.168.1.20',laptop='192.168.1.42';
  const http=(head,body)=>ncConcat(ncText(head),body instanceof Uint8Array?body:ncText(String(body)));
  const json='{"service":"inventory","environment":"demo","activeHosts":12,"alerts":[],"capture":{"packets":458,"durationSeconds":67.369},"metadata":{"source":"NullCap synthetic lab","safe":true}}';
  ncDemoSend(all,base,local,api,49111,8080,9.02,[http(`POST /api/v1/telemetry HTTP/1.1\r\nHost: api.example.invalid\r\nContent-Type: application/json\r\nContent-Length: ${ncText(json).length}\r\n\r\n`,json)],'HTTP POST · JSON API');
  const response='{"accepted":true,"requestId":"demo-7b2f","nodesProcessed":12,"processingMs":28}';
  ncDemoSend(all,base,api,local,8080,49111,9.14,[http(`HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: ${ncText(response).length}\r\n\r\n`,response)],'HTTP 200 · JSON');
  const xml='<?xml version="1.0"?><inventory><device id="host-01"><ip>192.168.1.12</ip><status>active</status></device><device id="host-02"><ip>192.168.1.42</ip><status>active</status></device></inventory>';
  ncDemoSend(all,base,api,local,8080,49112,18.2,[http(`HTTP/1.1 200 OK\r\nContent-Type: application/xml\r\nContent-Length: ${ncText(xml).length}\r\n\r\n`,xml)],'HTTP 200 · XML');
  const png=ncDemoPNG();
  ncDemoSend(all,base,cdn,local,8080,49113,29.4,[http(`HTTP/1.1 200 OK\r\nContent-Type: image/png\r\nContent-Disposition: inline; filename="network-lab.png"\r\nContent-Length: ${png.length}\r\n\r\n`,png)],'HTTP 200 · PNG');
  const note='NullCap test capture\r\nEvidence: mock inventory report\r\nGenerated by a synthetic local scenario.\r\nNo production endpoints or user data.\r\n';
  ncDemoSend(all,base,nas,laptop,8080,49114,36.35,[http(`HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Disposition: attachment; filename="capture-summary.txt"\r\nContent-Length: ${ncText(note).length}\r\n\r\n`,note)],'HTTP attachment · TXT');
  const email='EHLO nullcap.local\r\nMAIL FROM:<lab@example.invalid>\r\nRCPT TO:<analyst@example.invalid>\r\nDATA\r\nFrom: NullCap Lab <lab@example.invalid>\r\nTo: Analyst <analyst@example.invalid>\r\nSubject: Report della cattura (demo)\r\nDate: Wed, 18 Nov 2026 14:00:00 +0100\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nQuesto e un messaggio dimostrativo, non contiene dati reali.\r\n\r\n.\r\nQUIT\r\n';
  ncDemoSend(all,base,laptop,nas,49222,25,42.7,[email],'SMTP DATA · email di prova');
  for(let i=0;i<90;i++){
    const b=new Uint8Array(12+160),dv=new DataView(b.buffer);b[0]=0x80;b[1]=0;dv.setUint16(2,1000+i);dv.setUint32(4,250000+i*160);dv.setUint32(8,0xa7f128ee);
    for(let j=0;j<160;j++)b[12+j]=ncULawEncode(Math.round(3200*Math.sin(Math.PI*2*(440+40*Math.sin(i*.06))*(i*160+j)/8000)));
    all.push(ncDemoPacket({src:laptop,dst:nas,srcPort:16000,dstPort:16002,protocol:'UDP',ts:base+48+i*.020,body:b,info:'RTP · G.711 PCMU (scenario demo)'}));
  }
  return all.filter(Boolean).sort((a,b)=>a.ts-b.ts);
}
const ncOriginalCreateDemo=createDemo;
createDemo=function(){return ncEnrichDemo(ncOriginalCreateDemo());};
