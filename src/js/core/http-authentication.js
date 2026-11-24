'use strict';
/* NullCap 3.1.2 — offline HTTP/1.x authentication provenance and response analysis.
   Reconstructed secrets exist ONLY in volatile capture state. Never write them to
   localStorage, case JSON, CSV exports or console logs. No network requests. */
const NC312_VALUE_LIMIT=8192;
const NC312_EVENT_LIMIT=5000;
const NC312_SENSITIVE_COOKIE=/^(?:session(?:id|_id|token|_token)?|sid|jsessionid|phpsessid|connect\.sid|asp\.net_sessionid|auth(?:_?token)?|access_?token|refresh_?token|id_?token|jwt|token|remember_?token)$/i;
const NC312_IDENTITY_KEY=/^(?:user(?:name|_name|id|_id)?|email|e_?mail|login|account|identifier|userid|user_id|principal)$/i;
const NC312_IGNORE_FIELD=/(?:csrf|xsrf|nonce|authenticity|password[_\-]?hint|password[_\-]?strength|password[_\-]?policy|token[_\-]?type|token[_\-]?expires|_expiry|expires[_\-]?in)/i;
function nc312SensitiveKey(name){
  const raw=String(name||'').replace(/\[([^\]]+)\]/g,'.$1').replace(/([a-z])([A-Z])/g,'$1_$2').toLowerCase();
  if(NC312_IGNORE_FIELD.test(raw))return false;
  if(ncHttpSensitiveField(raw))return true;
  const compact=raw.replace(/[^a-z0-9]/g,'');
  return ['token','jwt','secret','clientsecret','authtoken','sessiontoken','sessionid','sessionkey','apikey','apiaccesskey','authkey','accesskey','authorization','bearertoken','oauthaccesstoken','oauthtoken','idtoken','refreshtoken','phpsessid','jsessionid','sid'].includes(compact);
}
function nc312Display(value){
  const val=String(value??'');
  return JSON.stringify(val.slice(0,NC312_VALUE_LIMIT))+(val.length>NC312_VALUE_LIMIT?' [TRONCATO]':'');
}
function nc312ExtractAuthentication(head,rawHeader,body,{response=false,compressed=false}={}){
  const hits=[],identities=[],seen=new Set(),spans=[];
  const raw=String(rawHeader||'');
  const headerSize=raw.length+4;
  const bodyText=body&&body.length<=NC_HTTP_AUTH_MAX_BODY?NC_UTF8.decode(body):'';
  const bodyByteIndex=i=>headerSize+new TextEncoder().encode(bodyText.slice(0,Math.max(0,i))).length;
  function add(where,name,value,start=-1,end=-1,identity=false,kind='credential'){
    if(value===null||value===undefined||typeof value==='object'||String(value)==='')return;
    if(hits.length+identities.length>=50)return;
    const field=String(name).replace(/[\x00-\x1f\x7f]/g,'').slice(0,140);
    const val=String(value);
    const key=where+'\u0000'+field+'\u0000'+val;
    if(seen.has(key))return;seen.add(key);
    const item={where,field,value:val,kind};
    (identity?identities:hits).push(item);
    if(!identity&&Number.isInteger(start)&&Number.isInteger(end)&&start>=0&&end>start){
      spans.push({start,end,kind});
    }
  }
  const identity=name=>NC312_IDENTITY_KEY.test(String(name).replace(/[\[\].-]/g,'_'));
  const bodySpan=(i,len)=>compressed||i<0?[-1,-1]:[bodyByteIndex(i),bodyByteIndex(i+len)];
  function keyValues(rawParams,where,offset,isCookie=false){
    let pos=0;
    for(const item of String(rawParams).split(isCookie?';':'&').slice(0,200)){
      const eq=item.indexOf('=');
      if(eq<1){pos+=item.length+1;continue;}
      let key=item.slice(0,eq).trim(),value=item.slice(eq+1).trim();
      try{key=decodeURIComponent(key.replace(/\+/g,' '));value=decodeURIComponent(value.replace(/\+/g,' '));}catch{}
      const sensitive=isCookie?NC312_SENSITIVE_COOKIE.test(key):nc312SensitiveKey(key);
      const start=offset<0?-1:offset+pos+item.indexOf('=')+1;
      if(sensitive)add(where,key,value,start,start<0?-1:start+item.slice(eq+1).length,false,NC312_SENSITIVE_COOKIE.test(key)||/token|key|jwt|secret/i.test(key)?'token':'credential');
      else if(identity(key))add(where,key,value,-1,-1,true);
      pos+=item.length+1;
    }
  }
  if(!response){
    for(const header of ['authorization','proxy-authorization']){
      const val=String(head.headers[header]||'');
      const m=val.match(/^\s*(Basic|Bearer)\s+(\S+)/i);
      if(!m)continue;
      const found=raw.match(new RegExp('(?:^|\\r\\n)'+header+'\\s*:\\s*(?:Basic|Bearer)\\s+(\\S+)','i'));
      const at=found?found.index+found[0].lastIndexOf(found[1]):-1;
      const end=at<0?-1:at+found[1].length;
      if(m[1].toLowerCase()==='basic'){
        try{
          const bytes=Uint8Array.from(atob(m[2]),c=>c.charCodeAt(0));
          const text=NC_UTF8.decode(bytes),split=text.indexOf(':');
          if(split>=0){
            add('Authorization Basic','username',text.slice(0,split),-1,-1,true);
            add('Authorization Basic','password',text.slice(split+1),at,end,false,'credential');
          }else add('Authorization Basic','credenziale Basic',m[2],at,end,false,'credential');
        }catch{add('Authorization Basic','token Base64 (non decodificabile)',m[2],at,end,false,'credential');}
      }else add('Authorization Bearer','token',m[2],at,end,false,'token');
    }
    for(const header of ['x-api-key','api-key','x-auth-token','x-access-token','x-authorization']){
      const val=String(head.headers[header]||'');if(!val)continue;
      const match=raw.match(new RegExp('(?:^|\\r\\n)'+header+'\\s*:\\s*([^\\r\\n]+)','i'));
      const at=match?match.index+match[0].lastIndexOf(match[1]):-1;
      add('Header HTTP',header,val,at,at<0?-1:at+val.length,false,'token');
    }
    const cookie=String(head.headers.cookie||'');
    if(cookie){const m=raw.match(/(?:^|\r\n)cookie\s*:\s*([^\r\n]+)/i);const at=m?m.index+m[0].lastIndexOf(m[1]):-1;keyValues(cookie,'Cookie HTTP',at,true);}
    const target=head.startLine.split(/\s+/)[1]||'';
    const qAt=target.indexOf('?');
    if(qAt>=0){
      const params=target.slice(qAt+1).split('#')[0];
      const uriAt=raw.indexOf(target);
      if(params.length<=16384)keyValues(params,'Query string',uriAt<0?-1:uriAt+qAt+1);
    }
  }else{
    // Responses can carry newly issued session tokens in JSON or Set-Cookie.
    const cookies=raw.match(/(?:^|\r\n)set-cookie\s*:\s*([^\r\n]+)/ig)||[];
    for(const entry of cookies.slice(0,40)){
      const one=entry.replace(/^(?:\r\n)?set-cookie\s*:\s*/i,'').split(';')[0];
      const match=one.match(/^\s*([^=]+)=([^\r\n]*)/);
      if(!match||!NC312_SENSITIVE_COOKIE.test(match[1].trim())||!match[2])continue;
      const at=raw.indexOf(entry);
      const valueAt=at<0?-1:at+entry.indexOf(match[2]);
      add('Set-Cookie',match[1].trim(),match[2],valueAt,valueAt<0?-1:valueAt+match[2].length,false,'token');
    }
  }
  const type=String(head.headers['content-type']||'').split(';')[0].trim().toLowerCase();
  if(bodyText){
    if(!response&&(type==='application/x-www-form-urlencoded'||(!type||type==='text/plain')&&/^[^\s&=]{1,80}=/.test(bodyText))){
      let at=0;
      for(const part of bodyText.split('&').slice(0,200)){
        const eq=part.indexOf('=');if(eq<1){at+=part.length+1;continue;}
        let key=part.slice(0,eq),val=part.slice(eq+1);
        try{key=decodeURIComponent(key.replace(/\+/g,' '));val=decodeURIComponent(val.replace(/\+/g,' '));}catch{}
        const [start,end]=bodySpan(at+eq+1,part.length-eq-1);
        if(nc312SensitiveKey(key))add('Modulo HTTP',key,val,start,end,false,/token|key|jwt|secret/i.test(key)?'token':'credential');
        else if(identity(key))add('Modulo HTTP',key,val,-1,-1,true);
        at+=part.length+1;
      }
    }
    if(type==='application/json'||type.endsWith('+json')||(!type||type==='text/plain'||type==='application/octet-stream')&&/^\s*[\[{]/.test(bodyText)){
      try{
        const obj=JSON.parse(bodyText);let visited=0;
        function walk(item,path,depth){
          if(++visited>1500||depth>8||!item||typeof item!=='object')return;
          if(Array.isArray(item)){for(const sub of item.slice(0,60))walk(sub,path,depth+1);return;}
          for(const [name,value] of Object.entries(item).slice(0,100)){
            if(value&&typeof value==='object'){walk(value,path.concat(name),depth+1);continue;}
            if(value===null||value===undefined)continue;
            const isSensitive=nc312SensitiveKey(name),isIdentity=!response&&identity(name);
            if(!isSensitive&&!isIdentity)continue;
            const serialized=JSON.stringify(value),keyPattern=JSON.stringify(name);
            const keyAt=bodyText.indexOf(keyPattern);
            const valueAt=bodyText.indexOf(serialized,Math.max(0,keyAt));
            const [start,end]=bodySpan(valueAt,serialized.length);
            add('JSON',path.concat(name).slice(-6).join('.'),value,start,end,isIdentity&&!isSensitive,/token|key|jwt|secret/i.test(name)?'token':'credential');
          }
        }
        walk(obj,[],0);
      }catch{}
    }
    if(!response&&type==='multipart/form-data'){
      const boundary=String(head.headers['content-type']||'').match(/boundary=(?:"([^"]+)"|([^;\s]+))/i);
      if(boundary){
        const marker='--'+(boundary[1]||boundary[2]);let at=0,steps=0;
        while((at=bodyText.indexOf(marker,at))>=0&&steps++<120){
          const headerEnd=bodyText.indexOf('\r\n\r\n',at+marker.length);
          if(headerEnd<0||headerEnd-at>1200)break;
          const segmentHead=bodyText.slice(at+marker.length,headerEnd);
          const name=segmentHead.match(/\bname\s*=\s*(?:"([^"]+)"|([^;\s]+))/i);
          const next=bodyText.indexOf(marker,headerEnd+4);
          if(next<0)break;
          const valStart=headerEnd+4,valEnd=Math.max(valStart,next-2);
          if(name&&!/\bfilename\s*=/i.test(segmentHead)){
            const key=name[1]||name[2],value=bodyText.slice(valStart,valEnd);
            const [start,end]=bodySpan(valStart,valEnd-valStart);
            if(nc312SensitiveKey(key))add('Multipart',key,value,start,end,false,/token|key|jwt|secret/i.test(key)?'token':'credential');
            else if(identity(key))add('Multipart',key,value,-1,-1,true);
          }
          at=next;
        }
      }
    }
    if(/(?:xml|\+xml|text\/plain)/.test(type)){
      const tags=/<([a-z][\w:-]{0,90})\b[^>]*>([^<]{1,8192})<\/\1\s*>/ig;let m,count=0;
      while((m=tags.exec(bodyText))&&count++<100){
        const key=m[1],val=m[2];const [start,end]=bodySpan(m.index+m[0].indexOf(val),val.length);
        if(nc312SensitiveKey(key))add('XML',key,val,start,end,false,/token|key|jwt|secret/i.test(key)?'token':'credential');
        else if(!response&&identity(key))add('XML',key,val,-1,-1,true);
      }
    }
  }
  if(!hits.length)return null;
  const parts=head.startLine.split(/\s+/);
  const method=response?'':parts[0].toUpperCase();
  const route=response?'':ncHttpSafeTarget(parts[1]);
  const hasPassword=hits.some(x=>/(?:password|passwd|pwd|passcode|passphrase)/i.test(x.field)&&!x.where.startsWith('Authorization Basic'));
  const isLogin=!response&&(hasPassword||/\b(?:login|signin|auth(?:enticate)?|session|token)\b/i.test(route)&&hits.some(x=>x.where!=='Cookie HTTP'));
  const label=response?(hits.some(h=>h.kind==='credential')?'Credenziali HTTP':'Token HTTP'):isLogin?'Login HTTP':'Autenticazione HTTP';
  const title=response?label+' · '+head.startLine.split(/\s+/).slice(0,2).join(' '):label+' · '+method+' '+route;
  const context=response?head.startLine:method+' '+route+' HTTP/1.x';
  const preview=['CREDENZIALI / TOKEN RILEVATI IN HTTP IN CHIARO',
    'Richiesta / risposta: '+context,
    'ATTENZIONE: i valori sono visibili in chiaro solo in questa sessione locale.',
    'Non copiare immagini o schermate contenenti segreti reali.','',
    ...(identities.length?['Identificativi associati:',...identities.map(x=>'  '+x.where+' · '+x.field+' = '+nc312Display(x.value)),'']:[]),
    'Valori sensibili (in chiaro):',
    ...hits.map(x=>'  '+x.where+' · '+x.field+' = '+nc312Display(x.value)),
    '',response?'Token osservato nella risposta. La sua emissione non dimostra da sola un login riuscito.':'Esito della richiesta: in attesa di correlazione HTTP.'];
  return {title,label,context,method,route,hits,identities,spans,isLogin,previewText:preview.join('\n'),metadata:context+' · '+hits.length+' campo/i in chiaro'};
}
function nc312ExposurePackets(run,start,messageEnd,auth){
  const ids=new Set();
  for(const range of auth.spans||[]){
    for(const id of ncUsedPackets(run,start+range.start,start+range.end))ids.add(id);
  }
  if(!ids.size)for(const id of ncUsedPackets(run,start,messageEnd))ids.add(id);
  for(const id of ids){
    const p=state.packets[id-1];if(!p)continue;
    p.hasSensitiveData=true;
    p.sensitiveKinds??=new Set();
    for(const hit of auth.hits)p.sensitiveKinds.add(hit.kind);
  }
  return [...ids].slice(0,240);
}
/* The 3.1.2 response-only heuristic has been retired.
   3.1.3 performs event/session correlation in v313-correlation.js. */
