import config from '../aleph.config.json' with { type: 'json' };
const issuer=new URL(config.judgeIssuer);
const candidates=[
 ['current-code',config.judgeIssuer+'/.well-known/jwks.json'],
 ['origin-root',issuer.origin+'/.well-known/jwks.json'],
 ['issuer-openid',config.judgeIssuer+'/.well-known/openid-configuration'],
 ['origin-openid',issuer.origin+'/.well-known/openid-configuration'],
];
for(const [name,url] of candidates) {
  try {
    const response=await fetch(url,{redirect:'manual',
       signal:AbortSignal.timeout(9000),headers:{accept:'application/json'}});
    let shape='non-json';
    if(response.ok){
      const body=await response.json().catch(()=>null);
      if(body && typeof body==='object'){
        if(Array.isArray(body.keys))shape='jwks key count '+body.keys.length;
        else if(typeof body.jwks_uri==='string')shape='openid jwks host '+new URL(body.jwks_uri).hostname;
        else shape='json keys '+Object.keys(body).join(',').slice(0,80);
      }
    }
    console.log('PUBLIC_JWKS '+name+' HTTP '+response.status+' shape='+shape);
  }catch(e) {
    console.log('PUBLIC_JWKS '+name+' unavailable '+String(e.name||'error'));
  }
}
