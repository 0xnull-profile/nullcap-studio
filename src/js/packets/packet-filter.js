'use strict';
/* Safe, local expression compiler for packet table filters. No eval or dynamic code. */
function nc31FilterTokens(expression){
  if(typeof expression!=='string'||expression.length>600)throw new Error('Espressione troppo lunga (massimo 600 caratteri).');
  const tokens=[];let i=0;
  while(i<expression.length){
    if(/\s/.test(expression[i])){i++;continue;}
    if(expression[i]==='('||expression[i]===')'){tokens.push(expression[i++]);continue;}
    let buf='',quote='',escaped=false;
    while(i<expression.length){
      const c=expression[i];
      if(escaped){buf+=c;escaped=false;i++;continue;}
      if(quote){if(c==='\\'){escaped=true;buf+=c;i++;continue;}if(c===quote){quote='';buf+=c;i++;continue;}buf+=c;i++;continue;}
      if(c==='"'||c==="'"){quote=c;buf+=c;i++;continue;}
      if(/\s/.test(c)||c==='('||c===')')break;
      buf+=c;i++;
    }
    if(quote)throw new Error('Virgolette non chiuse nel filtro.');
    if(buf)tokens.push(buf);
    if(tokens.length>110)throw new Error('Troppe condizioni nel filtro.');
  }
  return tokens;
}
function nc31FilterTerm(raw){
  const m=/^([a-z][a-z0-9_.]*)(>=|<=|!=|=|:|>|<)(.+)$/i.exec(raw);
  const text=v=>String(v??'').toLowerCase();
  const unquote=x=>x.length>=2&&((x[0]==='"'&&x.at(-1)==='"')||(x[0]==="'"&&x.at(-1)==="'"))?x.slice(1,-1).replace(/\\([\\"'])/g,'$1'):x;
  if(!m){let q=text(unquote(raw));if(!q)throw new Error('Condizione vuota.');return p=>[p.id,p.src,p.dst,p.protocol,p.transport,p.info,p.flags,p.srcPort,p.dstPort].some(v=>text(v).includes(q));}
  let [,key,operator,rawValue]=m;key=key.toLowerCase();let value=unquote(rawValue).trim();
  if(!value)throw new Error('Valore mancante per '+key+'.');
  const numeric={id:p=>[p.id],frame:p=>[p.id],len:p=>[p.length],bytes:p=>[p.length],time:p=>[p.rel],port:p=>[p.srcPort,p.dstPort],srcport:p=>[p.srcPort],dstport:p=>[p.dstPort],payload:p=>[p.payloadBytes]};
  const getter=numeric[key];
  if(getter){
    const target=Number(value);if(!Number.isFinite(target)||target<0)throw new Error('Numero non valido per '+key+'.');
    return p=>{const list=getter(p).filter(Number.isFinite);if(!list.length)return false;const comparator=v=>({':':()=>v===target,'=':()=>v===target,'!=':()=>v!==target,'>':()=>v>target,'<':()=>v<target,'>=':()=>v>=target,'<=':()=>v<=target}[operator])();return operator==='!='?list.every(comparator):list.some(comparator);};
  }
  if(operator!==':'&&operator!=='='&&operator!=='!=')throw new Error('Per '+key+' usa il confronto testuale con ":".');
  value=text(value);
  const strings={ip:p=>[p.src,p.dst],src:p=>[p.src],dst:p=>[p.dst],proto:p=>[p.protocol],protocol:p=>[p.protocol],transport:p=>[p.transport],flags:p=>[p.flags],info:p=>[p.info],source:p=>[p.source],confidence:p=>[p.protocolSource],timestamp:p=>[Number.isFinite(p.ts)?'known':'missing'],tag:p=>[state.investigation?.bookmarks?.[p.id]?'marked':'unmarked'],note:p=>[state.investigation?.bookmarks?.[p.id]?.note||'']};
  if(key==='has'){
    if(!['payload','raw','timestamp'].includes(value))throw new Error('Valori di has: payload, raw, timestamp.');
    return p=>({payload:()=>p.payloadBytes>0,raw:()=>Boolean(p.raw?.length),timestamp:()=>Number.isFinite(p.ts)})[value]();
  }
  const access=strings[key];if(!access)throw new Error('Campo non riconosciuto: '+key+'.');
  return p=>{
    const matched=access(p).some(v=>key==='tag'||key==='timestamp'||key==='confidence'?text(v)===value:key==='flags'?text(v).split(/\s*,\s*/).includes(value):text(v).includes(value));
    return operator==='!='?!matched:matched;
  };
}
function nc31CompileFilter(expression){
  const tokens=nc31FilterTokens(expression.trim());
  if(!tokens.length)return ()=>true;
  let at=0,depth=0;
  const peek=()=>tokens[at]?.toUpperCase(),consume=()=>tokens[at++];
  function atom(){
    if(++depth>18)throw new Error('Troppi livelli di parentesi.');
    let fn;
    if(peek()==='('){consume();fn=or();if(peek()!==')')throw new Error('Parentesi di chiusura mancante.');consume();}
    else if(peek()===')'||at>=tokens.length)throw new Error('Condizione attesa dopo un operatore.');
    else if(peek()==='AND'||peek()==='OR')throw new Error('Operatore senza condizione.');
    else fn=nc31FilterTerm(consume());
    depth--;return fn;
  }
  function not(){if(peek()==='NOT'){consume();const test=not();return p=>!test(p);}return atom();}
  function and(){let fn=not();while(at<tokens.length&&peek()!==')'&&peek()!=='OR'){
    if(peek()==='AND')consume();const left=fn,right=not();fn=p=>left(p)&&right(p);
  }return fn;}
  function or(){let fn=and();while(peek()==='OR'){consume();const left=fn,right=and();fn=p=>left(p)||right(p);}return fn;}
  const test=or();if(at<tokens.length)throw new Error('Token inatteso: '+tokens[at]+'.');
  return test;
}
