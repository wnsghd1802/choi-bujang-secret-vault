import assert from 'node:assert/strict';
import { test } from 'node:test';
import { readFile } from 'node:fs/promises';
import { createClient } from '@supabase/supabase-js';
import { createAuthHandler } from '../src/auth-api.mjs';
const env={SUPABASE_URL:'https://unit-test.supabase.co',SUPABASE_SECRET_KEY:'test-server-key'};
const userId='11111111-1111-4111-8111-111111111111';
const expiry=Math.floor(Date.now()/1000)+3600;
const part=o=>Buffer.from(JSON.stringify(o)).toString('base64url');
const jwt=[part({alg:'HS256',typ:'JWT'}),part({sub:userId,exp:expiry,iat:expiry-3600,role:'authenticated'}),'synthetic-signature'].join('.');
const providerSession={access_token:jwt,refresh_token:'synthetic-refresh',expires_at:expiry,expires_in:3600,token_type:'bearer',
  user:{id:userId,email:'test@example.test',user_metadata:{private:'not-returned'}}};
const req=(body,headers={})=>({method:'POST',headers:{'content-type':'application/json',...headers},body});
const res=()=>({headers:{},setHeader(k,v){this.headers[k]=v},status(code){this.code=code;return this},json(body){this.body=body;return this}});
function factoryWith(fetcher){return (url,key,options)=>createClient(url,key,{...options,global:{fetch:fetcher}});}

test('login uses official SDK on server and exposes only the user session, never server key',async()=>{
  let called,clients=0;
  const factory=factoryWith(async(url,init)=>{called={url:String(url),headers:new Headers(init.headers),body:JSON.parse(init.body)};
    return new Response(JSON.stringify(providerSession),{status:200,headers:{'content-type':'application/json'}})});
  const handler=createAuthHandler({env,clientFactory:(...args)=>{clients++;return factory(...args)}});
  const response=res();await handler(req({action:'login',email:'test@example.test',password:'synthetic-password'}),response);
  assert.equal(response.code,200);assert.equal(response.body.session.user.id,userId);
  assert.match(called.url,/grant_type=password/);assert.equal(called.headers.get('apikey'),env.SUPABASE_SECRET_KEY);
  assert.equal(called.body.password,'synthetic-password');
  assert.deepEqual(Object.keys(response.body.session.user),['id']);
  assert.doesNotMatch(JSON.stringify(response.body),/test-server-key|synthetic-password|not-returned/);
  assert.equal(response.headers['Cache-Control'],'no-store');
  await handler(req({action:'login',email:'test@example.test',password:'synthetic-password'}),res());assert.equal(clients,2);
});

test('refresh uses SDK refreshSession; logout sends only presented user token to logout endpoint',async()=>{
  let call;
  const handler=createAuthHandler({env,clientFactory:factoryWith(async(url,init)=>{
    call={url:String(url),headers:new Headers(init.headers),body:init.body};
    return String(url).includes('/logout') ? new Response(null,{status:204}) : new Response(JSON.stringify(providerSession),{headers:{'content-type':'application/json'}});
  })});
  let response=res();await handler(req({action:'refresh',refresh_token:'synthetic-refresh'}),response);
  assert.equal(response.code,200);assert.match(call.url,/grant_type=refresh_token/);
  assert.equal(JSON.parse(call.body).refresh_token,'synthetic-refresh');
  response=res();await handler(req({action:'logout'},{authorization:`Bearer ${jwt}`}),response);
  assert.equal(response.code,200);assert.deepEqual(response.body,{signedOut:true});
  assert.match(call.url,/logout\?scope=local/);assert.equal(call.headers.get('authorization'),`Bearer ${jwt}`);
});

test('provider login failure is sanitized and never passes provider diagnostics to browser',async()=>{
  const handler=createAuthHandler({env,clientFactory:factoryWith(async()=>new Response(JSON.stringify({error_code:'invalid_credentials',msg:'PRIVATE_UPSTREAM_DETAIL'}),{status:400,headers:{'content-type':'application/json','x-supabase-api-version':'2024-01-01'}}))});
  const response=res();await handler(req({action:'login',email:'test@example.test',password:'synthetic-password'}),response);
  assert.equal(response.code,401);assert.doesNotMatch(JSON.stringify(response.body),/PRIVATE_UPSTREAM_DETAIL|synthetic-password|test-server-key/);
});

test('malformed, unsupported and non-JSON login requests cannot invoke the provider',async()=>{
  let calls=0;const handler=createAuthHandler({env,clientFactory:()=>{calls++;throw new Error('must not run')}});
  for(const [request,status] of [[{method:'GET'},405],[{method:'POST',headers:{},body:{}},415],[req('{bad'),400],
    [req({action:'login'}),400],[req({action:'refresh'}),401],[req({action:'logout'}),401]]){
    const response=res();await handler(request,response);assert.equal(response.code,status);
  }
  assert.equal(calls,0);
});

test('browser requests only same-origin APIs and imports no Supabase configuration or SDK',async()=>{
  const source=await readFile(new URL('../src/browser-app.js',import.meta.url),'utf8');
  assert.doesNotMatch(source,/supabase-js|browser-config|sb_publishable_|sb_secret_|rest\/v1|https:\/\//);
  assert.match(source,/fetch\('\/api\/auth'/);assert.match(source,/api\('\/api\/notes'/);
});
