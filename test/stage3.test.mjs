import assert from 'node:assert/strict';
import { test } from 'node:test';
import { generateKeyPair, exportJWK, createLocalJWKSet, SignJWT, jwtVerify } from 'jose';
import { createLoginVerifier } from '../src/verify-login.mjs';
import { createNotesHandler } from '../src/notes-api.mjs';
import { noteOwnerId } from '../src/note-owner.mjs';
import { contentDigest } from '../src/recovery-core.mjs';
import config from '../aleph.config.json' with { type: 'json' };

const A = '11111111-1111-4111-8111-111111111111';
const B = '22222222-2222-4222-8222-222222222222';
const RUN = '33333333-3333-4333-8333-333333333333';
const NOTE = '44444444-4444-4444-8444-444444444444';
const key = await generateKeyPair('ES256');
const other = await generateKeyPair('ES256');
const jwk = await exportJWK(key.publicKey);
const verifier = createLoginVerifier({ config, judgeKeySet: createLocalJWKSet({ keys: [jwk] }),
  supabaseClient: { auth: { async getClaims(token) {
    try { const {payload} = await jwtVerify(token, key.publicKey, { issuer: config.identityProvider.issuer, audience: 'authenticated' });
      return {data:{claims:payload},error:null}; } catch {return {data:null,error:new Error('unverified')}}
  } } },
});
async function token(overrides = {}, privateKey = key.privateKey) {
  const now = Math.floor(Date.now()/1000);
  return new SignJWT({ iss: config.judgeIssuer, aud: new URL(config.publicAppUrl).hostname,
    sub: A, iat: now, exp: now+300, aleph_run: RUN, aleph_role: 'judge', aleph_identity: 'a', ...overrides })
    .setProtectedHeader({alg:'ES256'}).sign(privateKey);
}
const good = await token();
// Match the real collection/item URL and query parsing contracts.
const request = (method, body, id, jwt = good) => {
  const isItem = id !== null && id !== undefined;
  return { method, body, url: isItem ? '/api/notes/' + id : '/api/notes',
    query: isItem ? {id} : {},
    headers: jwt ? {authorization:`Bearer ${jwt}`} : {} };
};
function response() { return {headers:{}, setHeader(k,v){this.headers[k]=v;}, status(code){this.code=code;return this;},json(body){this.body=body;return this;}}; }
function fakeDb(initial = []) {
  const rows = structuredClone(initial);
  let calls=0;
  const backups=[];
  return { rows, backups, get calls(){return calls;}, from(table) {
    assert.equal(table,'notes'); calls++;
    let action='select', values, mode, filter=[];
    const query={ select(){return query;},order(){return query;},eq(k,v){filter.push([k,v]);return query;},
      insert(v){action='insert';values=v;return query;},update(v){action='update';values=v;return query;},delete(){action='delete';return query;},
      single(){mode='one';return query;},maybeSingle(){mode='one';return query;},
      async abortSignal(){
        if(action==='insert'){
          if(rows.some(r=>r.id===values.id))return {data:null,error:{code:'23505'}};
          rows.push({...values});return {data:{...values},error:null};
        }
        const found=rows.filter(r=>filter.every(([k,v])=>r[k]===v));
        if(action==='update')found.forEach(r=>Object.assign(r,values));
        const result=found.map(r=>({...r}));
        if(action==='delete')found.forEach(r=>rows.splice(rows.indexOf(r),1));
        return {data:mode ? (result[0]??null) : result,error:null};
      }
    };return query;
  },
  // Judge B now uses an atomic create-with-private-backup RPC instead of a raw insert.
  // Reproduce that current contract inside this disposable in-memory fixture.
  rpc(name, p) {
    if(name==='update_test_note_with_backup'){
      return {async abortSignal(){
        const found=rows.find(row=>row.id===p.p_id && row.owner_id===p.p_owner_id);
        if(!found)return {data:[],error:null};
        const copy=backups.find(row=>row.id===p.p_id);
        if(copy){
          if(copy.owner_id!==p.p_owner_id || copy.run_id!==p.p_run_id ||
             copy.identity!=='b'||copy.content_sha256!==contentDigest(copy.content))
            return {data:null,error:{code:'backup_mismatch'}};
        }else backups.push({...found,run_id:p.p_run_id,identity:'b',
          content_sha256:contentDigest(found.content)});
        found.title=p.p_title;
        found.content=p.p_content;
        return {data:[{...found}],error:null};
      }};
    }
    assert.equal(name, 'create_test_note_with_backup');
    return {async abortSignal() {
      if (typeof p.p_id !== 'string' || typeof p.p_owner_id !== 'string'
          || typeof p.p_run_id !== 'string' || !p.p_title
          || p.p_hash !== contentDigest(p.p_content)) {
        return {data:null,error:{code:'invalid_private_backup'}};
      }
      if (rows.some(row=>row.id===p.p_id) || backups.some(row=>row.id===p.p_id)) {
        return {data:null,error:{code:'23505'}};
      }
      const note={id:p.p_id,owner_id:p.p_owner_id,title:p.p_title,content:p.p_content};
      rows.push(note);
      backups.push({...note,run_id:p.p_run_id,identity:'b',content_sha256:p.p_hash});
      return {data:[{...note}],error:null};
    }};
  }};
}

test('no token, altered signature, expired token, wrong audience and wrong issuer cannot read or write', async () => {
  const invalid=[null,'broken',await token({},other.privateKey), await token({iat:Math.floor(Date.now()/1000)-100,exp:Math.floor(Date.now()/1000)-10}),
    await token({aud:'other-service'}),await token({iss:'https://unknown.example/auth/v1'})];
  const db=fakeDb();
  for(const jwt of invalid) for(const item of [false,true]) for(const method of (item?['GET','PUT','DELETE']:['GET','POST'])) {
    const res=response();
    await createNotesHandler({item,db,verifyLogin:verifier})(request(method,{title:'test',body:'test'},NOTE,jwt),res);
    assert.equal(res.code,401);
    assert.ok(res.body.error);
    assert.equal(res.headers['Cache-Control'],'no-store');
  }
  assert.equal(db.calls,0);
});

test('verified student claims pass, expired or wrong student audience fail', async () => {
  const jwt=await token({iss:config.identityProvider.issuer,aud:'authenticated',role:'authenticated'});
  assert.equal((await verifier(`Bearer ${jwt}`)).userId,A);
  assert.equal(await verifier(`Bearer ${await token({iss:config.identityProvider.issuer,aud:'other',role:'authenticated'})}`),null);
  assert.equal(await verifier(`Bearer ${await token({iss:config.identityProvider.issuer,aud:'authenticated',role:'authenticated',exp:1})}`),null);
});

test('CRUD uses verified owner, returns required shapes, lists own notes and deleted notes return 404', async () => {
  const db=fakeDb([{id:NOTE,owner_id:B,title:'other',content:'fiction'}]);
  const collection=createNotesHandler({db,verifyLogin:verifier});
  const item=createNotesHandler({item:true,db,verifyLogin:verifier});
  let res=response();
  await collection(request('POST',{title:'my test',body:'fiction',owner_id:B,userId:B,role:'admin'}),res);
  assert.equal(res.code,201);
  assert.match(res.body.id,/^[a-f0-9-]{36}$/);
  assert.deepEqual(Object.keys(res.body).sort(),['body','id','title']);
  const id=res.body.id;
  assert.equal(db.rows.find(r=>r.id===id).owner_id,noteOwnerId(await verifier(`Bearer ${good}`)));
  res=response(); await collection(request('GET'),res);
  assert.equal(res.body.length,1); assert.equal(res.body[0].id,id);
  res=response(); await item(request('GET',null,id),res); assert.equal(res.code,200);
  res=response(); await item(request('PUT',{title:'updated',body:'updated'},id),res);
  assert.equal(res.body.body,'updated'); assert.equal(db.rows.find(r=>r.id===id).owner_id,noteOwnerId(await verifier(`Bearer ${good}`)));
  res=response(); await item(request('DELETE',null,id),res); assert.equal(res.body.deleted,true);
  res=response(); await item(request('GET',null,id),res); assert.equal(res.code,404);
  // Stage 4: known IDs of other owners are protected as well.
  res=response(); await item(request('GET',null,NOTE),res); assert.equal(res.code,404);
});

test('supplied UUID is retained, duplicates conflict, malformed inputs fail before DB', async () => {
  const db=fakeDb();const handler=createNotesHandler({db,verifyLogin:verifier});
  let res=response();await handler(request('POST',{id:NOTE,title:'test',body:'fiction'}),res);
  assert.equal(res.body.id,NOTE);
  res=response();await handler(request('POST',{id:NOTE,title:'test',body:'fiction'}),res);assert.equal(res.code,409);
  for(const body of ['{broken',[],{title:'',body:'x'},{id:'bad',title:'x',body:'x'},{title:'x',body:5}]){
    const calls=db.calls;res=response();await handler(request('POST',body),res);assert.equal(res.code,400);assert.equal(db.calls,calls);
  }
});

test('database errors never reach clients and unsupported methods return 405', async () => {
  const db={from(){throw new Error('PRIVATE_DATABASE_DETAIL')}};
  const handler=createNotesHandler({db,verifyLogin:verifier});let res=response();
  await handler(request('GET'),res);assert.equal(res.code,502);assert.doesNotMatch(JSON.stringify(res.body),/PRIVATE_DATABASE_DETAIL/);
  res=response();await handler(request('PATCH'),res);assert.equal(res.code,405);
});

test('both owners keep CRUD, cannot read/update/delete each other, and cannot transfer ownership', async () => {
  const db=fakeDb();
  const list=createNotesHandler({db,verifyLogin:verifier});
  const item=createNotesHandler({item:true,db,verifyLogin:verifier});
  const tokens=[good,await token({sub:B,aleph_identity:'b'})];
  const ids=[];
  for(let i=0;i<2;i++){
    const res=response();
    await list(request('POST',{title:'owner test',body:'fiction'},null,tokens[i]),res);
    assert.equal(res.code,201);ids.push(res.body.id);
  }
  for(let i=0;i<2;i++){
    let res=response();await list(request('GET',null,null,tokens[i]),res);
    assert.deepEqual(res.body.map(n=>n.id),[ids[i]]);
    res=response();await item(request('GET',null,ids[i],tokens[i]),res);assert.equal(res.code,200);
    res=response();await item(request('PUT',{title:'mine',body:'edited'},ids[i],tokens[i]),res);assert.equal(res.code,200);
    const snapshot=structuredClone(db.rows);
    for(const method of ['GET','PUT','DELETE']){
      res=response();await item(request(method,{title:'intrusion',body:'rejected'},ids[1-i],tokens[i]),res);
      assert.equal(res.code,404);assert.deepEqual(db.rows,snapshot);
      assert.deepEqual(Object.keys(res.body),['error']);
    }
    res=response();await item(request('PUT',{title:'transfer',body:'rejected',owner_id:i===0?B:A},ids[i],tokens[i]),res);
    assert.equal(res.code,403);assert.deepEqual(db.rows,snapshot);
  }
  for(let i=0;i<2;i++){
    let res=response();await item(request('DELETE',null,ids[i],tokens[i]),res);assert.equal(res.code,200);
    res=response();await item(request('GET',null,ids[i],tokens[i]),res);assert.equal(res.code,404);
  }
});

test('judge identities a/b with same verified sub and run cannot share notes', async () => {
  const db = fakeDb();
  const list = createNotesHandler({ db, verifyLogin: verifier });
  const item = createNotesHandler({ item: true, db, verifyLogin: verifier });
  const aToken = good;
  const bToken = await token({ aleph_identity: 'b' }); // Same sub and aleph_run.
  const r1 = response();
  await list(request('POST', { title: 'a note', body: 'synthetic' }, null, aToken), r1);
  assert.equal(r1.code, 201);
  const idA = r1.body.id;
  const r2 = response();
  await list(request('POST', { title: 'b note', body: 'synthetic' }, null, bToken), r2);
  assert.equal(r2.code, 201);
  assert.equal(db.backups.length, 1, 'only judge B creates a private backup');
  assert.equal(db.backups[0].content_sha256, contentDigest('synthetic'));
  const idB = r2.body.id;
  const ownerA = db.rows.find(row => row.id === idA).owner_id;
  const ownerB = db.rows.find(row => row.id === idB).owner_id;
  assert.notEqual(ownerA, ownerB);
  assert.equal(ownerA, noteOwnerId(await verifier(`Bearer ${aToken}`)));
  assert.equal(ownerB, noteOwnerId(await verifier(`Bearer ${bToken}`)));
  for (const [active, own, other] of [[aToken,idA,idB],[bToken,idB,idA]]) {
    const ownRes = response();
    await item(request('GET', null, own, active), ownRes);
    assert.equal(ownRes.code, 200);
    const listRes = response();
    await list(request('GET', null, null, active), listRes);
    assert.deepEqual(listRes.body.map(row => row.id), [own]);
    for (const method of ['GET','PUT','DELETE']) {
      const denied = response();
      await item(request(method, { title:'wrong', body:'wrong' }, other, active), denied);
      assert.equal(denied.code, 404);
    }
  }
});

test('student owner key remains original verified user UUID', () => {
  assert.equal(noteOwnerId({ kind: 'student', userId: A }), A);
  assert.equal(noteOwnerId({ kind: 'judge', userId: A, runId: RUN, identity: 'x' }), null);
});
