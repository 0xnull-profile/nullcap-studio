'use strict';
/* 3.1.3: passive HTTP transaction/session correlation. It NEVER verifies credentials
   by contacting a server. All comparisons use volatile capture bytes only.
   Confidence describes observed network evidence, not credential validity. */
const NC313_FOLLOWUP_SECONDS=90;
const NC313_PRIOR_SECONDS=300;
const NC313_MAX_FOLLOWUPS=24;
const NC313_PROTECTED_PATH=/(?:^|\/)(?:admin|dashboard|account|profile|private|secure|member|members|portal|settings|user(?:s)?\/me|my[-_]?account|intranet|restricted|controlpanel)(?:\/|$)/i;
const NC313_AUTH_PATH=/(?:^|\/)(?:login|log-in|signin|sign-in|authenticate|authentication|auth|signon|session)(?:\/|$)/i;
const NC313_FAILED_REDIRECT=/(?:^|\/)(?:login|signin|sign-in|log-in|denied|unauthorized)(?:\/|$)|[?&](?:error|invalid|failed)=/i;
function nc313Time(event){return Number.isFinite(event?.rel)?event.rel:Infinity;}
function nc313Frame(event){return Number(event?.packetIds?.[0])||Infinity;}
function nc313Compare(a,b){return nc313Time(a)-nc313Time(b)||nc313Frame(a)-nc313Frame(b)||a.order-b.order;}
function nc313Path(path){
  let value=String(path||'/').trim();
  if(/^https?:\/\//i.test(value)){try{value=new URL(value).pathname;}catch{return '';}}
  value=value.split(/[?#]/)[0];
  if(!value.startsWith('/'))return '';
  return value.replace(/\/{2,}/g,'/').replace(/\/$/,'')||'/';
}
function nc313Host(host){return String(host||'').trim().toLowerCase().replace(/\.$/,'').slice(0,250);}
function nc313Origin(event){return [event.src,event.dst,event.dstPort,nc313Host(event.host||event.headers?.host)].join('|');}
function nc313Cookies(text){
  const cookies=new Map();
  for(const part of String(text||'').split(';').slice(0,80)){
    const i=part.indexOf('=');if(i<1)continue;
    const name=part.slice(0,i).trim().toLowerCase(),value=part.slice(i+1).trim().replace(/^"|"$/g,'');
    if(name&&value)cookies.set(name,value);
  }
  return cookies;
}
function nc313SessionIssued(response){
  if(!response)return [];
  const hits=response.authHits||[];
  return hits.filter(h=>h.kind==='token'&&h.value&&
    (h.where==='Set-Cookie'||/token|jwt|session|auth|key/i.test(h.field)))
    .slice(0,24).map(h=>({name:h.field.toLowerCase(),value:h.value,source:h.where}));
}
function nc313TokenUsed(request,token){
  if(!token||!request)return false;
  if(token.source==='Set-Cookie')return nc313Cookies(request.headers?.cookie).get(token.name)===token.value;
  const bearer=String(request.headers?.authorization||'').match(/^\s*Bearer\s+(\S+)/i);
  if(bearer?.[1]===token.value)return true;
  return ['x-auth-token','x-access-token','x-api-key','api-key'].some(k=>request.headers?.[k]===token.value);
}
function nc313HasAuthReuse(req,loginResponse,loginReq){
  const issued=nc313SessionIssued(loginResponse);
  const used=issued.filter(t=>nc313TokenUsed(req,t));
  const priorCookie=nc313Cookies(loginReq?.headers?.cookie);
  const newlyIssued=used.filter(t=>t.source!=='Set-Cookie'||priorCookie.get(t.name)!==t.value);
  return {reused:used.length>0,newlyIssued:newlyIssued.length>0,
    oldCookie:!!(req?.headers?.cookie&&loginReq?.headers?.cookie&&[...nc313Cookies(req.headers.cookie)].some(([n,v])=>priorCookie.get(n)===v))};
}
function nc313JsonStatus(body){
  if(!/^\s*\{/.test(body||''))return {ok:false,no:false,explicit:false};
  try{
    const obj=JSON.parse(body);if(!obj||typeof obj!=='object'||Array.isArray(obj))return {ok:false,no:false,explicit:false};
    const status=String(obj.status||obj.result||'').toLowerCase();
    const explicitSuccess=obj.authenticated===true||obj.loggedIn===true||obj.logged_in===true||
      obj.success===true||/^(authenticated|logged[-_]?in|success)$/.test(status);
    const explicitFailure=obj.authenticated===false||obj.loggedIn===false||obj.logged_in===false||
      obj.success===false||/^(unauthorized|invalid|denied|failure|failed|error)$/.test(status)||
      /(?:invalid[_ -]?(?:credentials|password)|bad[_ -]?credentials|login[_ -]?failed)/i.test(String(obj.error||''));
    const genericOkay=obj.ok===true;
    return {ok:explicitSuccess||genericOkay,no:explicitFailure,explicit:explicitSuccess,weak:genericOkay&&!explicitSuccess};
  }catch{return {ok:false,no:false,explicit:false};}
}
function nc313LoginPage(response){
  if(!response)return false;
  const body=String(response.bodyText||'');
  if(/<input\b[^>]*type\s*=\s*["']?password\b/i.test(body))return true;
  if(/\b(?:incorrect password|invalid credentials|authentication failed|login failed|sign in to continue|please log in to continue)\b/i.test(body))return true;
  return false;
}
function nc313Content(response){
  if(!response||response.statusCode<200||response.statusCode>=300||nc313LoginPage(response))return false;
  const type=String(response.headers?.['content-type']||'').toLowerCase();
  // Non-empty HTML/JSON/text can be evidence of content access, not evidence of restricted access.
  return (/html|json|xml|text\//i.test(type)&&response.bodyLength>60)||response.bodyLength>400;
}
function nc313RedirectPath(response){
  const target=String(response?.headers?.location||'');
  if(!target)return '';
  return nc313Path(target);
}
function nc313Failure(response){
  if(!response)return {strong:false,clue:''};
  const code=response.statusCode;
  const parsed=nc313JsonStatus(response.bodyText);
  if(parsed.no)return {strong:true,clue:'Esito applicativo negativo nella risposta al login'};
  if(code===401||code===403)return {strong:true,clue:`Risposta al login HTTP ${code} (accesso rifiutato o non autorizzato)`};
  if(code>=300&&code<400&&NC313_FAILED_REDIRECT.test(String(response.headers?.location||'')))
    return {strong:true,clue:'Redirect della risposta verso una pagina di login/errore'};
  if(nc313LoginPage(response)&&code>=200&&code<300)return {strong:false,clue:'La risposta presenta nuovamente un modulo di login o un messaggio di errore'};
  if(code>=400)return {strong:false,clue:`HTTP ${code}: richiesta fallita, ma motivo delle credenziali non accertato`};
  return {strong:false,clue:''};
}
function nc313PairEvents(events){
  const byFlow=new Map();
  for(const event of events){
    if(!byFlow.has(event.flowKey))byFlow.set(event.flowKey,[]);
    byFlow.get(event.flowKey).push(event);
  }
  const transactions=[];
  for(const flow of byFlow.values()){
    const requests=flow.filter(e=>e.type==='request').sort(nc313Compare);
    const responses=flow.filter(e=>e.type==='response').sort(nc313Compare);
    let j=0;
    for(const req of requests){
      let response=null;
      while(j<responses.length){
        const candidate=responses[j];
        const timed=Number.isFinite(req.rel)&&Number.isFinite(candidate.rel);
        if(timed&&candidate.rel<req.rel-.015){j++;continue;}
        if(timed&&candidate.rel>req.rel+300)break;
        if(!timed&&nc313Frame(candidate)<nc313Frame(req)){j++;continue;}
        if(candidate.statusCode>=100&&candidate.statusCode<200){j++;continue;}
        response=candidate;j++;break;
      }
      if(response){req.response=response;response.request=req;}
      req.origin=nc313Origin(req);
      transactions.push(req);
    }
  }
  return transactions.sort(nc313Compare);
}
function nc313SuccessAssessment(login,allRequests){
  const response=login.response;
  const favor=[],against=[],limits=[],traces=[];
  let score=0,strongNegative=false,corroboration=0;
  const line=(request,why)=>({
    request:request.method+' '+request.route,
    status:request.response?.statusCode||null,
    frameId:request.packetIds?.[0]||null,
    responseFrameId:request.response?.packetIds?.[0]||null,
    why
  });
  traces.push(line(login,'Tentativo di autenticazione rilevato'));
  if(!response){
    limits.push('La risposta diretta alla richiesta non e\' disponibile o non e\' correlabile.');
    return {outcome:'unknown',score:0,favor,against,limits,traces,followups:[],confidence:'insufficiente'};
  }
  traces[0].status=response.statusCode;
  traces[0].responseFrameId=response.packetIds?.[0]||null;
  const failure=nc313Failure(response);
  const explicit=nc313JsonStatus(response.bodyText);
  if(failure.clue){against.push(failure.clue);if(failure.strong)strongNegative=true;}
  if(response.statusCode>=200&&response.statusCode<300&&explicit.ok){
    score+=explicit.explicit?75:30;
    favor.push(explicit.explicit?'La risposta applicativa dichiara esplicitamente autenticazione/esito positivo':'La risposta applicativa contiene ok:true (indizio generico)');
  }
  const issued=nc313SessionIssued(response);
  const priorCookies=nc313Cookies(login.headers?.cookie);
  const newIssued=issued.filter(t=>t.source!=='Set-Cookie'||priorCookies.get(t.name)!==t.value);
  if(issued.length&&response.statusCode>=200&&response.statusCode<400){
    score+=newIssued.length?20:8;
    favor.push(newIssued.length?'La risposta emette una sessione/token nuovo rispetto alla richiesta':'La risposta riemette un valore di sessione gia\' presente');
  }
  const redirect=nc313RedirectPath(response);
  if(response.statusCode>=300&&response.statusCode<400&&redirect&&NC313_PROTECTED_PATH.test(redirect)){
    score+=12;favor.push('Redirect verso un percorso dall\'aspetto riservato: '+redirect);
  }
  const nextLogin=allRequests.find(e=>e!==login&&e.origin===login.origin&&e.isLogin&&nc313Time(e)>nc313Time(login));
  const stop=nextLogin?nc313Time(nextLogin):Infinity;
  const reqs=allRequests.filter(req=>req!==login&&req.origin===login.origin&&
    Number.isFinite(req.rel)&&Number.isFinite(response.rel)&&req.rel>response.rel+.000001&&
    req.rel<=response.rel+NC313_FOLLOWUP_SECONDS&&req.rel<stop)
    .slice(0,NC313_MAX_FOLLOWUPS);
  if(!Number.isFinite(response.rel))limits.push('Timestamp incompleti: non si possono attribuire con sicurezza richieste da altre connessioni.');
  const prev=allRequests.filter(req=>req!==login&&req.origin===login.origin&&
    Number.isFinite(req.rel)&&Number.isFinite(login.rel)&&req.rel<login.rel&&req.rel>=login.rel-NC313_PRIOR_SECONDS);
  let firstContent=false,firstReuse=false,baseline=false,followEvidence=false;
  const relevant=[];
  for(const req of reqs){
    const res=req.response;
    if(!res)continue;
    const path=nc313Path(req.route);
    if(!path||/\.(?:css|js|png|gif|jpg|jpeg|svg|woff2?|ico|map)$/i.test(path))continue;
    if(/(?:^|\/)(?:logout|signout)(?:\/|$)/i.test(path))continue;
    const use=nc313HasAuthReuse(req,response,login);
    const looksProtected=NC313_PROTECTED_PATH.test(path);
    const redirected=redirect&&path===redirect;
    const content=nc313Content(res);
    const valid=res.statusCode>=200&&res.statusCode<300&&!nc313LoginPage(res);
    const priorDeniedEvent=prev.find(old=>nc313Path(old.route)===path&&old.response&&
      (old.response.statusCode===401||old.response.statusCode===403||
        (old.response.statusCode>=300&&old.response.statusCode<400&&NC313_FAILED_REDIRECT.test(String(old.response.headers?.location||'')))));
    const priorDenied=Boolean(priorDeniedEvent);
    if(!valid&&!use.reused&&!redirected&&!priorDenied)continue;
    const notes=[];
    if(use.newlyIssued){notes.push('riutilizzo del token/cookie emesso dopo il login');if(!firstReuse){score+=30;firstReuse=true;}}
    else if(use.reused){notes.push('valore di sessione riutilizzato');if(!firstReuse){score+=13;firstReuse=true;}}
    else if(use.oldCookie){notes.push('cookie preesistente presente prima e dopo il login');}
    if(priorDenied&&valid){notes.push('stessa risorsa negata prima del login, ora HTTP '+res.statusCode);
      if(!baseline){score+=45;baseline=true;traces.unshift(line(priorDeniedEvent,'Accesso alla stessa risorsa prima del login: negato o reindirizzato al login'));}}
    if(redirected&&valid){notes.push('destinazione del redirect raggiunta (HTTP '+res.statusCode+')');score+=firstContent?5:20;}
    if(looksProtected&&valid){notes.push('percorso potenzialmente riservato con risposta '+res.statusCode);if(!firstContent)score+=16;}
    if(content&&(looksProtected||redirected||use.reused||priorDenied)){
      notes.push('contenuto applicativo ricevuto, non identificato come pagina di login');
      if(!firstContent){score+=12;firstContent=true;}
    }else if(content&&!looksProtected&&!redirected){
      // Public content after login is weak evidence, and never enough by itself.
      notes.push('contenuto ricevuto: non e\' noto se la risorsa sia pubblica');
      if(!firstContent){score+=4;firstContent=true;}
    }
    if(use.newlyIssued||priorDenied||redirected||(looksProtected&&valid))followEvidence=true;
    if(notes.length){relevant.push({req,notes});traces.push(line(req,notes.join('; ')));}
  }
  if(relevant.length){
    corroboration=relevant.length;
    favor.push(`Osservate ${relevant.length} richieste successive collegate allo stesso client e servizio; vedere la sequenza sotto.`);
    for(const item of relevant.slice(0,8))favor.push(`${item.req.method} ${item.req.route} → HTTP ${item.req.response.statusCode}: ${item.notes.join('; ')}`);
  }else if(!strongNegative){
    limits.push('Nessuna navigazione successiva collegabile con sufficiente attendibilita\' nei 90 secondi osservati.');
  }
  if(issued.length&&relevant.length===0)limits.push('Un cookie/token emesso non dimostra che sia stato accettato in una richiesta successiva.');
  if(!relevant.some(x=>x.notes.some(s=>s.includes('negata prima')))&&relevant.length)
    limits.push('Non e\' disponibile un controllo della stessa risorsa prima del login: potrebbe essere pubblica.');
  if(failure.clue&&!failure.strong)limits.push('Errore non univocamente attribuibile alla validita\' delle credenziali.');
  if(!response.bodyComplete)limits.push('Risposta HTTP parziale o non delimitata: la correlazione del corpo potrebbe essere incompleta.');
  if(strongNegative&&score>=50){
    limits.push('Indizi contrastanti: prevale la risposta di rifiuto del tentativo; le richieste successive potrebbero appartenere ad altre sessioni.');
  }
  let outcome;
  if(strongNegative)outcome='failed';
  else if(score>=70&&(explicit.explicit||followEvidence))outcome='strong';
  else if(response.statusCode>=400)outcome='unknown';
  else if(score>=26&&(explicit.ok||followEvidence||issued.length||corroboration))outcome='probable';
  else outcome='unknown';
  if(outcome==='strong')limits.push('Evidenza forte, ma non prova indipendente della validita\' attuale delle credenziali.');
  else if(outcome==='probable')limits.push('Correlazione indiziaria; non e\' una verifica certa delle credenziali.');
  else if(outcome==='unknown')limits.push('Il traffico osservato non consente di determinare l\'esito.');
  const confidence={strong:'alta (indizi convergenti)',probable:'media (indizi compatibili)',failed:'negativa per questo tentativo',unknown:'insufficiente'}[outcome];
  return {outcome,score:Math.min(100,score),favor,against,limits,traces,followups:relevant,confidence};
}
function nc313DirectAuthAssessment(req,requests){
  const res=req.response,favor=[],against=[],limits=[];
  const authTechnique=(req.authHits||[]).find(h=>h.where==='Authorization Basic'||h.where==='Authorization Bearer'||h.where==='Header HTTP')?.where||'header HTTP';
  const traces=[{request:req.method+' '+req.route,status:res?.statusCode||null,
    frameId:req.packetIds?.[0]||null,responseFrameId:res?.packetIds?.[0]||null,
    why:'Richiesta con autenticazione HTTP esplicita: '+authTechnique}];
  let score=0,outcome='unknown';
  if(!res){limits.push('Risposta HTTP assente: non e\' possibile valutare l\'esito.');}
  else{
    const failure=nc313Failure(res),json=nc313JsonStatus(res.bodyText);
    if(failure.clue)against.push(failure.clue);
    if(failure.strong)outcome='failed';
    else if(res.statusCode>=200&&res.statusCode<300){
      if(json.explicit){score+=70;favor.push('La risposta dichiara esplicitamente autenticazione riuscita.');}
      const protectedPath=NC313_PROTECTED_PATH.test(nc313Path(req.route));
      const content=nc313Content(res);
      const priorDenied=requests.find(x=>x!==req&&x.origin===req.origin&&
        nc313Path(x.route)===nc313Path(req.route)&&
        Number.isFinite(x.rel)&&Number.isFinite(req.rel)&&x.rel<req.rel&&x.rel>=req.rel-NC313_PRIOR_SECONDS&&
        x.response&&(x.response.statusCode===401||x.response.statusCode===403));
      if(priorDenied){
        traces.unshift({request:priorDenied.method+' '+priorDenied.route,status:priorDenied.response.statusCode,
          frameId:priorDenied.packetIds?.[0]||null,responseFrameId:priorDenied.response.packetIds?.[0]||null,
          why:'Stessa risorsa rifiutata in precedenza'});
        score+=50;favor.push('La stessa risorsa era stata negata prima di questa richiesta.');
      }
      if(protectedPath){score+=20;favor.push('Risorsa dal percorso apparentemente protetto.');}
      if(content&&(protectedPath||priorDenied)){score+=15;favor.push('Il server ora restituisce contenuti applicativi.');}
      if(!priorDenied)limits.push('Non sappiamo se la risorsa fosse pubblica e se il server abbia effettivamente verificato il segreto.');
      if(score>=70&&(json.explicit||priorDenied))outcome='strong';
      else if(score>=26&&(protectedPath||priorDenied||json.explicit))outcome='probable';
    }
    if(res.statusCode>=400&&!failure.strong)limits.push('Errore HTTP senza prova che la causa sia la credenziale.');
    if(!res.bodyComplete)limits.push('Risposta HTTP incompleta o non delimitata.');
  }
  if(outcome==='strong')limits.push('Indizi forti, non validazione indipendente o attuale del segreto.');
  if(outcome==='probable')limits.push('Compatibile con accesso riuscito; un HTTP 200 da solo non e\' una conferma.');
  if(outcome==='unknown')limits.push('Il traffico osservato non consente di determinare l\'esito.');
  return {outcome,score,favor,against,limits,traces,followups:[],
    confidence:{strong:'alta (indizi convergenti)',probable:'media (indizi compatibili)',failed:'negativa per questa richiesta',unknown:'insufficiente'}[outcome]};
}
function nc313AttachAnalysis(asset,req,analysis){
  asset.authOutcome=analysis.outcome;
  asset.authConfidence=analysis.confidence;
  asset.authScore=analysis.score;
  asset.authEvidence=analysis;
  asset.authOutcomeReason=analysis.favor[0]||analysis.against[0]||analysis.limits[0]||'Indizi insufficienti';
  asset.httpResponseFrameIds=req.response?.packetIds||[];
  let extra='\n\n--- ANALISI DI SESSIONE (passiva, indiziaria) ---\n';
  extra+='Valutazione: '+nc313OutcomeLabel(asset)+'\nConfidenza: '+analysis.confidence+'\n';
  extra+='Risposta HTTP: '+(req.response?'HTTP '+req.response.statusCode:'non osservata')+'\n';
  if(req.response?.authHits?.length){
    extra+='\nToken/cookie osservati nella risposta (visibili localmente):\n';
    for(const hit of req.response.authHits.slice(0,15))extra+='  '+hit.where+' · '+hit.field+' = '+nc312Display(hit.value)+'\n';
  }
  if(analysis.favor.length)extra+='\nINDIZI A FAVORE:\n'+analysis.favor.map(x=>' + '+x).join('\n')+'\n';
  if(analysis.against.length)extra+='\nINDIZI CONTRARI:\n'+analysis.against.map(x=>' - '+x).join('\n')+'\n';
  if(analysis.limits.length)extra+='\nLIMITI:\n'+analysis.limits.map(x=>' ! '+x).join('\n')+'\n';
  extra+='\nSEQUENZA E FRAME:\n'+analysis.traces.map(t=>' #'+(t.frameId||'?')+' '+t.request+' → '+(t.status?'HTTP '+t.status:'risposta N/D')+
    (t.responseFrameId?' [risposta #'+t.responseFrameId+']':'')+'\n   '+t.why).join('\n')+'\n';
  asset.previewText+=extra;
}
function nc313CorrelateHTTP(){
  const requests=nc313PairEvents(state.httpEvents||[]);
  const byId=new Map((state.loot||[]).map(asset=>[asset.id,asset]));
  for(const req of requests){
    const pairedAsset=byId.get(req.response?.assetId);
    if(pairedAsset){
      pairedAsset.httpRequestRoute=req.route;
      pairedAsset.description+=' · richiesta associata: '+req.method+' '+req.route;
    }
    const asset=byId.get(req.assetId);
    if(!asset||!asset.authFinding)continue;
    asset.httpResponseStatus=req.response?.statusCode||null;
    asset.httpResponseFrameIds=req.response?.packetIds||[];
    if(req.response?.assetId){
      const responseAsset=byId.get(req.response.assetId);
      if(responseAsset){responseAsset.relatedLoginId=req.isLogin?asset.id:null;responseAsset.relatedRequestId=asset.id;}
    }
    const explicitAuth=(req.authHits||[]).some(hit=>
      hit.where==='Authorization Basic'||hit.where==='Authorization Bearer'||hit.where==='Header HTTP');
    if(!req.isLogin&&!explicitAuth){
      asset.authOutcome='unknown';
      asset.authOutcomeReason='Cookie o dato sensibile osservato: non e\' necessariamente un tentativo di login.';
      continue;
    }
    const analysis=req.isLogin?nc313SuccessAssessment(req,requests):nc313DirectAuthAssessment(req,requests);
    nc313AttachAnalysis(asset,req,analysis);
  }
  nc313TriageLoot();
}
function nc313OutcomeLabel(asset){
  if(asset.authDirection==='response')return asset.authResponseCredential?'CREDENZIALI ESPOSTE':'TOKEN OSSERVATO';
  if(!asset.authIsLogin&&!asset.authEvidence)return 'AUTENTICAZIONE';
  return ({strong:'INDIZI FORTI',probable:'ACCESSO PROBABILE',failed:'ACCESSO RIFIUTATO',unknown:'ESITO NON DETERMINABILE'})[asset.authOutcome]||'ESITO NON DETERMINABILE';
}
function nc313SameBytes(a,b){
  if(!a||!b||a.length!==b.length)return false;
  for(let i=0;i<a.length;i++)if(a[i]!==b[i])return false;
  return true;
}
function nc313TriageLoot(){
  const assets=state.loot||[];
  const seen=new Map(),received=new Map();
  for(const asset of assets){
    asset.secondary=false;asset.secondaryReason='';asset.repeatCount=1;asset.repeatAssets=[];
    if(asset.authFinding){
      const event=(state.httpEvents||[]).find(e=>e.assetId===asset.id);
      const hits=event?.authHits||[];
      const onlyCookie=asset.authDirection==='request'&&hits.length>0&&hits.every(h=>h.where==='Cookie HTTP');
      if(asset.authDirection==='response'&&!asset.authResponseCredential){
        asset.secondary=true;
        asset.secondaryReason=asset.relatedLoginId?'Token/cookie riportato anche nell\'episodio di login':'Token emesso dal server senza un login correlato';
      }else if(onlyCookie){
        asset.secondary=true;asset.secondaryReason='Cookie di sessione osservato durante una normale richiesta';
      }
      const signature=hits.map(h=>h.where+'\0'+h.field+'\0'+h.value).sort().join('\0');
      if(signature&&asset.authDirection==='request'&&!asset.authIsLogin&&!onlyCookie){
        const key=event?.origin+'|'+asset.authDirection+'|'+signature;
        if(received.has(key)){
          asset.secondary=true;asset.secondaryReason='Ripetizione dello stesso token/credenziale sullo stesso servizio';
          const first=received.get(key);first.repeatCount++;first.repeatAssets.push(asset.id);
        }else received.set(key,asset);
      }
    }else if(asset.kind==='api'){
      asset.secondary=true;
      asset.secondaryReason='Risposta JSON/XML ordinaria conservata per consultazione';
    }
    if(!asset.authFinding&&asset.data?.length>0){
      const key=asset.kind+'|'+asset.contentType+'|'+asset.data.length+'|'+asset.src+'|'+asset.dst;
      const group=seen.get(key)||[];
      const match=group.find(x=>nc313SameBytes(x.data,asset.data));
      if(match){asset.secondary=true;asset.secondaryReason='Artefatto identico gia\' presente';match.repeatCount++;match.repeatAssets.push(asset.id);}
      else{group.push(asset);seen.set(key,group);}
    }
  }
  state.lootSecondaryCount=assets.filter(a=>a.secondary).length;
}
