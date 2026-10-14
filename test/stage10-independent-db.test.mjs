import {test} from 'node:test';
import assert from 'node:assert/strict';
import config from '../aleph.config.json' with {type:'json'};
import {getServerDb} from '../src/server-db-config.mjs';

const studentDb=new URL(config.identityProvider.issuer).origin;
const independent='https://independent-judge-b.supabase.co';
test('an independently provisioned judge DB is not the student JWT issuer',()=>{
  assert.notEqual(independent,studentDb);
  assert.deepEqual(getServerDb({
     SUPABASE_URL:independent,
     SUPABASE_SERVICE_ROLE_KEY:'legacy-role-secret-for-fixture',
  }),{url:independent,secretKey:'legacy-role-secret-for-fixture'});
});

test('normal production DB secret takes precedence, legacy service role fallback works',()=>{
  assert.deepEqual(getServerDb({SUPABASE_URL:studentDb,
     SUPABASE_SECRET_KEY:'placeholder-secret-for-fixture',
     SUPABASE_SERVICE_ROLE_KEY:'other-old-secret-key',
  }),{url:studentDb,secretKey:'placeholder-secret-for-fixture'});
  assert.deepEqual(getServerDb({SUPABASE_URL:studentDb,
     SUPABASE_SERVICE_ROLE_KEY:'older-service-role-fixture',
  }),{url:studentDb,secretKey:'older-service-role-fixture'});
});

test('invalid, public, malformed or credential-bearing DB origins are never accepted',()=>{
 const cases=[
 {SUPABASE_URL:independent,SUPABASE_SECRET_KEY:'sb_publishable_x'},
 {SUPABASE_URL:'http://independent-judge-b.supabase.co',SUPABASE_SECRET_KEY:'sufficient-secret'},
 {SUPABASE_URL:'https://bad.example',SUPABASE_SECRET_KEY:'sufficient-secret'},
 {SUPABASE_URL:'https://user:pw@independent-judge-b.supabase.co',SUPABASE_SECRET_KEY:'sufficient-secret'},
 {SUPABASE_URL:'https://independent-judge-b.supabase.co/hidden',SUPABASE_SECRET_KEY:'sufficient-secret'},
 {SUPABASE_URL:independent},
 {SUPABASE_URL:studentDb,SUPABASE_SECRET_KEY:'short'},
 ];
 for(const c of cases)assert.equal(getServerDb(c),null,JSON.stringify({url:c.SUPABASE_URL}));
});
