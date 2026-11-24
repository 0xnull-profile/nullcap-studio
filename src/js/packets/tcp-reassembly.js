'use strict';
/* NullCap TCP reassembly A12: offline, deterministic, first-observed-byte policy.
 * No decryption, application message inference or missing byte fabrication.
 * Pure engine; original frame buffers are never modified.
 * RFC 9293 sequence semantics, IPv4/IPv6 fragmentation with provenance.
 */
const NullCapTCPReassembler = (() => {
  const SIDE_LIMIT = 32 * 1024 * 1024;
  const FRAGMENT_LIMIT = 1024 * 1024;
  const MAX_FRAGMENT_GROUPS = 2048;
  const read16=(b,o)=>(b[o]*256+b[o+1]);
  const read32=(b,o)=>(b[o]*0x1000000+b[o+1]*65536+b[o+2]*256+b[o+3])>>>0;
  const v4=(b,o)=>Array.from(b.subarray(o,o+4)).join('.');
  const v6=(b,o)=>Array.from({length:8},(_,i)=>read16(b,o+i*2).toString(16)).join(':');
  const diff=(a,b)=>(((a-b+0x80000000)>>>0)-0x80000000);
  const endpoint=(ip,port)=>ip+'|'+port;
  const sameTuple=(x,y)=>(x.src===y.src&&x.dst===y.dst&&x.srcPort===y.srcPort&&x.dstPort===y.dstPort)||
    (x.src===y.dst&&x.dst===y.src&&x.srcPort===y.dstPort&&x.dstPort===y.srcPort);
  const isSyn=(x)=>Boolean(x.flags&2),isAck=(x)=>Boolean(x.flags&16),isFin=(x)=>Boolean(x.flags&1),isRst=(x)=>Boolean(x.flags&4);
  const CACHE=new WeakMap();

  function linkIP(raw,link){
    const b=raw;if(!(b instanceof Uint8Array)||b.length<4)return null;
    let off=0,ether=0;
    if(link===1){if(b.length<14)return null;ether=read16(b,12);off=14;
      for(let i=0;i<4&&[0x8100,0x88a8,0x9100].includes(ether);i++){
        if(off+4>b.length)return null;ether=read16(b,off+2);off+=4;
      }
    }else if(link===101||link===228||link===229){ether=link===228?0x0800:link===229?0x86dd:((b[0]>>>4)===4?0x0800:0x86dd);}
    else if(link===113){if(b.length<16)return null;ether=read16(b,14);off=16;}
    else if(link===276){if(b.length<20)return null;ether=read16(b,0);off=20;}
    else if(link===0||link===108){if(b.length<5)return null;off=4;ether=(b[off]>>>4)===4?0x0800:0x86dd;}
    else return null;
    if(ether===0x0800){
      if(off+20>b.length||(b[off]>>>4)!==4)return null;
      const hlen=(b[off]&15)*4,total=read16(b,off+2);
      if(hlen<20||off+hlen>b.length||total<hlen)return null;
      const flags=read16(b,off+6),fragOffset=(flags&0x1fff)*8,more=Boolean(flags&0x2000);
      if(b[off+9]!==6)return null;
      const end=Math.min(b.length,off+total);
      return {version:4,src:v4(b,off+12),dst:v4(b,off+16),proto:6,id:read16(b,off+4),
        offset:fragOffset,more,fragmented:Boolean(fragOffset||more),bytes:b.subarray(off+hlen,end),
        truncated:off+total>b.length,fragmentHeader:true};
    }
    if(ether!==0x86dd||off+40>b.length||(b[off]>>>4)!==6)return null;
    const payloadLen=read16(b,off+4),originalEnd=off+40+payloadLen,end=Math.min(b.length,originalEnd);
    let next=b[off+6],pos=off+40,frag=null;
    for(let i=0;i<16;i++){
      if([0,43,60,135].includes(next)){
        if(pos+2>end)return null;
        const len=(b[pos+1]+1)*8;if(len<8||pos+len>end)return null;
        next=b[pos];pos+=len;
      }else if(next===51){
        if(pos+2>end)return null;const len=(b[pos+1]+2)*4;
        if(len<8||pos+len>end)return null;next=b[pos];pos+=len;
      }else if(next===44){
        if(pos+8>end)return null;
        const f=read16(b,pos+2);frag={id:read32(b,pos+4),offset:f&0xfff8,more:!!(f&1),proto:b[pos]};
        next=b[pos];pos+=8;break;
      }else break;
    }
    if(!frag&&next!==6)return null;
    if(frag&&!([6,0,43,60,51,135].includes(frag.proto)))return null;
    return {version:6,src:v6(b,off+8),dst:v6(b,off+24),proto:frag?.proto??next,id:frag?.id??null,
      offset:frag?.offset??0,more:frag?.more??false,fragmented:Boolean(frag&&(frag.more||frag.offset)),
      bytes:b.subarray(pos,end),truncated:originalEnd>b.length,fragmentHeader:!!frag};
  }

  function tcpFromIP(ip,meta,bytes,fragmentIds=[],flagsFromIP={}){
    let off=0,next=ip.proto;
    if(ip.version===6){
      for(let i=0;i<12;i++){
        if([0,43,60,135].includes(next)){
          if(off+2>bytes.length)return null;const len=(bytes[off+1]+1)*8;
          if(len<8||off+len>bytes.length)return null;next=bytes[off];off+=len;
        }else if(next===51){
          if(off+2>bytes.length)return null;const len=(bytes[off+1]+2)*4;
          if(len<8||off+len>bytes.length)return null;next=bytes[off];off+=len;
        }else break;
      }
    }
    if(next!==6||off+20>bytes.length)return null;
    const hlen=(bytes[off+12]>>>4)*4;
    if(hlen<20||off+hlen>bytes.length)return null;
    const flags=bytes[off+13];
    return {src:ip.src,dst:ip.dst,srcPort:read16(bytes,off),dstPort:read16(bytes,off+2),
      seq:read32(bytes,off+4),ack:read32(bytes,off+8),flags,
      bytes:bytes.subarray(off+hlen),packetId:meta.id,packetIds:fragmentIds.length?fragmentIds:[meta.id],
      rel:meta.rel,ts:meta.ts,truncated:!!(ip.truncated||flagsFromIP.truncated),
      ipFragments:fragmentIds.length||0,ipAmbiguous:!!flagsFromIP.ambiguous,
      ipVersion:ip.version};
  }
  function collect(packets){
    if(CACHE.has(packets))return CACHE.get(packets);
    const tcp=[],partial=[],groups=new Map(),groupList=[];let fragments=0,invalidFragments=0;
    for(const p of packets){
      if(!p?.raw)continue;
      const ip=linkIP(p.raw,p.linkType??1);if(!ip)continue;
      if(!ip.fragmented){const rec=tcpFromIP(ip,p,ip.bytes);if(rec)tcp.push(rec);continue;}
      fragments++;
      const key=[ip.version,ip.src,ip.dst,ip.id,ip.proto].join('|');
      let g=groups.get(key);
      const elapsed=g&&Number.isFinite(p.ts)&&Number.isFinite(g.lastTS)?p.ts-g.lastTS:0;
      const differentStart=g?.first&&ip.offset===0&&!g.parts.some(x=>x.offset===0&&
        x.bytes.length===ip.bytes.length&&x.bytes.every((byte,j)=>byte===ip.bytes[j]));
      // Guard against IPv4 Identification or IPv6 Fragment ID reuse on later datagrams.
      // A duplicate first fragment with identical bytes stays in the same generation.
      if(g&&(elapsed>60||differentStart||g.discarded))g=null;
      if(!g){
        if(groupList.length>=MAX_FRAGMENT_GROUPS){invalidFragments++;continue;}
        g={ip,parts:[],ids:[],first:null,last:null,hasEnd:false,discarded:false,
          ambiguous:false,invalid:false,bytes:0,lastTS:p.ts};groups.set(key,g);groupList.push(g);
      }
      g.lastTS=p.ts;
      if(ip.offset+ip.bytes.length>FRAGMENT_LIMIT||ip.truncated||(ip.more&&ip.bytes.length%8!==0)){
        // A later full retransmission can still recover this IP datagram.
        g.invalid=true;g.ids.push(p.id);continue;
      }
      if(ip.offset===0&&(!g.first||p.id<g.first.id))g.first=p;
      if(!ip.more){g.hasEnd=true;g.last=ip.offset+ip.bytes.length;}
      for(const old of g.parts){
        if(ip.offset<old.offset+old.bytes.length&&old.offset<ip.offset+ip.bytes.length){
          if(ip.version===6){g.discarded=true;invalidFragments++;break;}
          const start=Math.max(old.offset,ip.offset),end=Math.min(old.offset+old.bytes.length,ip.offset+ip.bytes.length);
          for(let at=start;at<end;at++)if(old.bytes[at-old.offset]!==ip.bytes[at-ip.offset]){g.ambiguous=true;break;}
        }
      }
      if(!g.discarded){g.parts.push({offset:ip.offset,bytes:ip.bytes,p});g.ids.push(p.id);g.bytes+=ip.bytes.length;}
    }
    for(const g of groupList){
      const first=g.first;
      if(g.discarded){partial.push({src:g.ip.src,dst:g.ip.dst,version:g.ip.version,ids:g.ids,issue:'overlap IPv6 rifiutato'});continue;}
      if(!g.parts.length){partial.push({src:g.ip.src,dst:g.ip.dst,version:g.ip.version,ids:g.ids,issue:'frammento IP non valido o troncato'});continue;}
      if(!first){partial.push({src:g.ip.src,dst:g.ip.dst,version:g.ip.version,ids:g.ids,issue:'frammento iniziale assente'});continue;}
      const ordered=g.parts.slice().sort((a,b)=>a.p.id-b.p.id);
      const total=g.hasEnd?g.last:Math.max(...ordered.map(x=>x.offset+x.bytes.length));
      if(total>FRAGMENT_LIMIT||total<=0){partial.push({src:g.ip.src,dst:g.ip.dst,version:g.ip.version,ids:g.ids,issue:'dimensione datagramma eccessiva'});continue;}
      const data=new Uint8Array(total),present=new Uint8Array(total);
      for(const part of ordered)for(let i=0;i<part.bytes.length;i++){
        const at=part.offset+i;if(at>=total)continue;
        if(!present[at]){present[at]=1;data[at]=part.bytes[i];}
      }
      let contiguous=0;while(contiguous<total&&present[contiguous])contiguous++;
      const complete=g.hasEnd&&contiguous===total;
      // Incomplete fragments: only expose the verified contiguous prefix; never pad holes.
      const ip={...g.ip,truncated:!complete};
      const rec=tcpFromIP(ip,first,data.subarray(0,contiguous),[...new Set(g.ids)].sort((a,b)=>a-b),{ambiguous:g.ambiguous,truncated:!complete});
      if(rec){rec.fragmentIncomplete=!complete;tcp.push(rec);}
      if(!complete||g.ambiguous)partial.push({src:g.ip.src,dst:g.ip.dst,version:g.ip.version,ids:g.ids,
        issue:!complete?'datagramma IP frammentato incompleto':'frammenti IPv4 sovrapposti con byte discordanti'});
    }
    tcp.sort((a,b)=>a.packetId-b.packetId);
    const result={tcp,partial,stats:{fragments,invalidFragments,groups:groupList.length}};
    CACHE.set(packets,result);return result;
  }

  function sessions(records){
    const list=[],idle=300;
    let current=null;
    for(const r of records){
      const newSyn=isSyn(r)&&!isAck(r);
      const currentSyn=current?.synSeq;
      const synDifferent=newSyn&&currentSyn!==null&&currentSyn!==undefined&&r.seq!==currentSyn;
      const idleTooLong=current&&Number.isFinite(r.ts)&&Number.isFinite(current.last.ts)&&r.ts-current.last.ts>idle;
      const restart=current&&(synDifferent||(isSyn(r)&&current.sealed&&r.packetId>current.closedAt)||
        (idleTooLong&&(newSyn||current.sealed))||
        (current.sealed&&!newSyn&&r.bytes.length&&r.packetId>current.closedAt+2));
      if(!current||restart){current={records:[],synSeq:null,first:r,last:r,sealed:false,closedAt:Infinity,
        fin:new Set(),rst:false,startedBySyn:newSyn};list.push(current);}
      if(newSyn&&current.synSeq===null)current.synSeq=r.seq;
      current.records.push(r);current.last=r;
      if(isFin(r))current.fin.add(endpoint(r.src,r.srcPort));
      if(isRst(r)||current.fin.size>=2){current.sealed=true;current.closedAt=r.packetId;current.rst ||= isRst(r);}
    }
    return list;
  }

  const lowerBound=(arr,at)=>{let low=0,high=arr.length;while(low<high){const mid=(low+high)>>1;if(arr[mid].end<=at)low=mid+1;else high=mid;}return low;};
  function assembleDirection(items,sideLimit=SIDE_LIMIT){
    const data=items.filter(x=>x.bytes?.length),syn=items.find(isSyn);
    const anchor=syn?((syn.seq+1)>>>0):(data[0]?.seq??items[0]?.seq??0);
    const start=x=>diff((x.seq+(isSyn(x)?1:0))>>>0,anchor);
    const ranges=[],duplicateFrames=new Set(),overlapFrames=new Set(),conflicts=[];
    let overlapBytes=0,conflictBytes=0,unique=0,truncated=false,capDrops=0;
    for(const item of data){
      let s=start(item),e=s+item.bytes.length,at=s;
      const existing=[];
      for(let i=lowerBound(ranges,s);i<ranges.length&&ranges[i].start<e;i++)existing.push(ranges[i]);
      const pieces=[];let overlap=false,hasConflict=false;
      for(const r of existing){
        if(r.start>at)pieces.push({start:at,end:Math.min(r.start,e)});
        const lo=Math.max(s,r.start),hi=Math.min(e,r.end);
        if(hi>lo){
          overlap=true;overlapBytes+=hi-lo;
          for(let pos=lo;pos<hi;pos++){
            if(r.bytes[pos-r.start]!==item.bytes[pos-s]){
              hasConflict=true;conflictBytes++;
              const last=conflicts.at(-1);
              if(last&&last.end===pos&&last.firstFrame===r.packetId&&last.otherFrame===item.packetId)last.end++;
              else if(conflicts.length<128)conflicts.push({start:pos,end:pos+1,firstFrame:r.packetId,otherFrame:item.packetId});
            }
          }
        }
        at=Math.max(at,r.end);
      }
      if(at<e)pieces.push({start:at,end:e});
      if(overlap)overlapFrames.add(item.packetId);
      if(hasConflict){overlapFrames.add(item.packetId);}
      let newSize=0;
      for(const p of pieces){
        if(unique>=sideLimit){truncated=true;capDrops+=p.end-p.start;continue;}
        const end=Math.min(p.end,p.start+sideLimit-unique);
        if(end<=p.start)continue;
        const range={start:p.start,end,bytes:item.bytes.subarray(p.start-s,end-s),packetId:item.packetId,
          packetIds:item.packetIds,rel:item.rel,seq:(item.seq+((p.start-s)+(isSyn(item)?1:0)))>>>0};
        const atIndex=lowerBound(ranges,range.start);
        ranges.splice(atIndex,0,range);unique+=end-p.start;newSize+=end-p.start;
        if(end<p.end){truncated=true;capDrops+=p.end-end;}
      }
      if(!newSize&&overlap)duplicateFrames.add(item.packetId);
    }
    const events=[],assembled=[],runs=[],gaps=[];
    let active=null,lastEnd=null,orderedBytes=0;
    for(const r of ranges){
      if(lastEnd!==null&&r.start>lastEnd){
        const gap={start:lastEnd,end:r.start,size:r.start-lastEnd,packetId:r.packetId};gaps.push(gap);active=null;
      }
      if(!active){active={start:r.start,end:r.end,parts:[],sources:[],offset:orderedBytes};runs.push(active);}
      active.end=r.end;active.parts.push(r.bytes);active.sources.push({start:r.start,end:r.end,frame:r.packetId,frames:r.packetIds});
      assembled.push(r.bytes);orderedBytes+=r.bytes.length;lastEnd=r.end;
      events.push({dir:'',kind:'data',bytes:r.bytes,packetId:r.packetId,packetIds:r.packetIds,seq:r.seq,rel:r.rel,
        start:r.start,end:r.end});
    }
    for(const gap of gaps)events.push({dir:'',kind:'gap',size:gap.size,packetId:gap.packetId,start:gap.start,end:gap.end});
    // A SYN records the beginning of the sequence space, but its SYN byte is not payload.
    const minStart=ranges.length?ranges[0].start:null;
    const missingHead=!!(syn&&minStart!==null&&minStart>0);
    if(missingHead){
      const head={start:0,end:minStart,size:minStart,packetId:ranges[0].packetId};gaps.unshift(head);
      events.push({dir:'',kind:'gap',size:head.size,packetId:head.packetId,start:head.start,end:head.end});
    }
    const fin=items.find(isFin),reset=items.some(isRst);
    return {ranges,runs,gaps,events,assembled,unique,anchor,missingHead,overlapBytes,
      duplicateFrames:duplicateFrames.size,overlapFrames:overlapFrames.size,conflicts,conflictBytes,
      truncated,capDrops,syn:!!syn,fin:!!fin,reset,
      capturedTruncated:items.some(x=>x.truncated||x.fragmentIncomplete),
      ipAmbiguous:items.some(x=>x.ipAmbiguous)};
  }
  function addPeerAckEvidence(side,opposite){
    if(!side.syn)return 0;
    let highest=null,frame=null;
    for(const peer of opposite){
      if(!isAck(peer))continue;
      const delta=diff(peer.ack,side.anchor);
      if(delta<0||delta>2*SIDE_LIMIT)continue;
      if(highest===null||delta>highest){highest=delta;frame=peer.packetId;}
    }
    if(highest===null)return 0;
    const highestObserved=side.ranges.at(-1)?.end??0;
    // One byte of slack accounts conservatively for an unseen FIN. No ACK data is fabricated.
    if(highest<=highestObserved+1||side.fin)return 0;
    const possible=highest-highestObserved-1;
    const gap={start:highestObserved,end:highestObserved+possible,size:possible,
      packetId:frame,evidence:'peer-ACK',inferred:true};
    side.gaps.push(gap);
    side.events.push({...gap,kind:'gap',dir:''});
    side.ackMissing=possible;
    return possible;
  }
  function createStream(packets,selected,options={}){
    if(!selected||selected.transport!=='TCP')throw Error('Seleziona un pacchetto TCP.');
    const parsed=collect(packets);
    const selectedTcp=parsed.tcp.find(r=>r.packetIds.includes(selected.id))||
      parsed.tcp.find(r=>r.packetId===selected.id);
    if(!selectedTcp)throw Error('Impossibile ricostruire i byte TCP del frame: intestazioni mancanti o frammentazione non risolta.');
    const all=parsed.tcp.filter(x=>sameTuple(x,selectedTcp));
    if(!all.length)throw Error('Nessuna conversazione TCP disponibile.');
    const grouped=sessions(all);
    const chosen=grouped.find(s=>s.records.some(r=>r.packetIds.includes(selected.id)))||grouped[0];
    const byId=new Map(packets.map(p=>[p.id,p]));
    const frameIds=[...new Set(chosen.records.flatMap(x=>x.packetIds))].sort((a,b)=>a-b);
    const session=frameIds.map(id=>byId.get(id)).filter(Boolean);
    const first=chosen.records[0],a={ip:first.src,port:first.srcPort},b={ip:first.dst,port:first.dstPort};
    const sides={a:[],b:[]};
    for(const r of chosen.records){const dir=r.src===a.ip&&r.srcPort===a.port?'a':'b';sides[dir].push(r);}
    const sideA=assembleDirection(sides.a,options.sideLimit??SIDE_LIMIT);
    const sideB=assembleDirection(sides.b,options.sideLimit??SIDE_LIMIT);
    addPeerAckEvidence(sideA,sides.b);
    addPeerAckEvidence(sideB,sides.a);
    const full={a:sideA,b:sideB};
    const events=[],assembled={a:sideA.assembled,b:sideB.assembled},limits={a:sideA.unique,b:sideB.unique};
    for(const dir of ['a','b'])for(const ev of full[dir].events)events.push({...ev,dir});
    events.sort((x,y)=>x.packetId-y.packetId||(x.kind==='gap'?-1:1));
    const relevantPartial=parsed.partial.filter(x=>
      ((x.src===a.ip&&x.dst===b.ip)||(x.src===b.ip&&x.dst===a.ip))&&
      x.ids?.some(id=>id>=chosen.first.packetId-4&&id<=chosen.last.packetId+4));
    const counters={gaps:sideA.gaps.length+sideB.gaps.length,duplicate:sideA.duplicateFrames+sideB.duplicateFrames,
      overlaps:sideA.overlapFrames+sideB.overlapFrames,overlapBytes:sideA.overlapBytes+sideB.overlapBytes,
      conflicts:sideA.conflictBytes+sideB.conflictBytes,ipFragments:chosen.records.reduce((s,x)=>s+x.ipFragments,0),
      incompleteIP:relevantPartial.length,packets:session.length,
      truncated:sideA.truncated||sideB.truncated||sideA.capturedTruncated||sideB.capturedTruncated,
      rst:chosen.rst};
    const ambiguous=sideA.conflicts.length>0||sideB.conflicts.length>0||sideA.ipAmbiguous||sideB.ipAmbiguous||
      relevantPartial.some(x=>/sovrappost|overlap/i.test(x.issue));
    const partial=counters.gaps>0||counters.truncated||counters.incompleteIP>0||
      !chosen.startedBySyn||!sideA.fin||!sideB.fin||chosen.rst;
    const quality=ambiguous?'ambiguous':partial?'partial':'continuous';
    const warnings=[];
    if(counters.gaps)warnings.push(counters.gaps+' lacune TCP osservate o dedotte da ACK: nessun byte mancante inventato.');
    if(sideA.ackMissing||sideB.ackMissing)warnings.push('ACK del peer indica possibili byte non acquisiti oltre la fine dei dati osservati; inferenza conservativa.');
    if(counters.duplicate)warnings.push(counters.duplicate+' frame duplicati/ritrasmessi eliminati senza duplicare i byte.');
    if(counters.overlaps)warnings.push(counters.overlaps+' frame con sovrapposizioni; i primi byte osservati hanno precedenza.');
    if(ambiguous)warnings.push('Sovrapposizioni con byte discordanti: ricostruzione ambigua, provenienza riportata nel manifesto.');
    if(counters.truncated)warnings.push('Cattura o limite di memoria tronca i dati: risultato parziale.');
    if(counters.incompleteIP)warnings.push(counters.incompleteIP+' datagrammi IPv4/IPv6 frammentati incompleti o ambigui rilevati.');
    if(!chosen.startedBySyn)warnings.push('Acquisizione iniziata senza SYN iniziale: origine dello stream non verificabile.');
    if(!sideA.fin||!sideB.fin)warnings.push('Non sono state osservate entrambe le chiusure FIN: fine dello stream non verificata.');
    if(chosen.rst)warnings.push('Connessione terminata con RST.');
    if(options.isDemo)warnings.push('Lo scenario demo contiene dati sintetici e non rappresenta una cattura reale.');
    warnings.push('TCP offline: dati cifrati non decifrati. Nessun byte mancante inventato; non sono messaggi applicativi.');
    return {a,b,session,events,assembled,limits,warnings,counters,quality,ambiguous,partial,
      reconstruction:full,sessionInfo:{startedBySyn:chosen.startedBySyn,terminatedByReset:chosen.rst,
        observedFin:{a:sideA.fin,b:sideB.fin},firstFrame:first.packetId,lastFrame:chosen.last.packetId},
      fragmentIssues:relevantPartial};
  }
  return {createStream,collect,assembleDirection,sessions,linkIP,tcpFromIP,seqDiff:diff,SIDE_LIMIT};
})();
if(typeof module!=='undefined'&&module.exports)module.exports=NullCapTCPReassembler;
