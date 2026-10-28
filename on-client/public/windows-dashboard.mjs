// KimJH 총공세 3일차 — 서버가 직접 읽은 Windows 정보와 SDP 상태를 분리한다.
// 실측값이 없으면 숫자를 만들지 않고 "확인 불가"로 표시한다.
const byId = id => document.getElementById(id);
const measure = byId('windows-dashboard-measure');
const state = byId('windows-dashboard-message');
const reasons = {
 WINDOWS_ONLY:'Windows가 아닌 환경이어서 조회할 수 없습니다.',
 POWERSHELL_UNAVAILABLE:'읽기 전용 PowerShell 조회를 실행할 수 없습니다.',
 READ_TIMED_OUT:'조회 시간이 초과되었거나 중단됐습니다.',
 READ_RESULT_UNVERIFIED:'조회 결과 형식을 검증할 수 없습니다.',
 NETWORK_QUERY_UNAVAILABLE:'네트워크 설정을 읽을 수 없습니다. 일반 사용자 접근 권한 또는 Windows 서비스를 확인하세요.',
 NETWORK_NO_IPV4:'조회 가능한 IPv4 네트워크 어댑터가 없습니다.',
 FIREWALL_QUERY_UNAVAILABLE:'방화벽 프로필을 읽을 수 없습니다. 권한 또는 Windows 서비스를 확인하세요.',
 FIREWALL_PROFILES_UNAVAILABLE:'조회 가능한 방화벽 프로필이 없습니다.',
 EVENT_LOG_UNAVAILABLE:'Windows 이벤트 로그를 읽지 못했습니다. 권한 또는 이벤트 로그 서비스를 확인하세요.',
};
const pname={Domain:'도메인',Private:'개인',Public:'공용'};
const actionName={Allow:'허용',Block:'차단',NotConfigured:'지정되지 않음'};
const labels={network:'네트워크',firewall:'Windows 방화벽',events:'Windows 경고·오류',sdp:'SDP'};
const ids=['network','firewall','events','sdp'];
const details=byId('windows-dashboard-details');
const historyBody=byId('windows-dashboard-history-body');
const history=[];
let running=false;

const make=(tag,value)=>{const n=document.createElement(tag);n.textContent=value;return n;};
function fmtTime(timestamp) {
 const d=new Date(timestamp);
 return Number.isFinite(d.getTime())?d.toLocaleString('ko-KR',{year:'numeric',month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit',second:'2-digit',timeZoneName:'short'}):'확인 불가';
}
const reason = item => reasons[item?.reason] || '이유를 확인할 수 없습니다.';
function card(id,value,time='확인 불가') {
 byId(`windows-${id}-summary`).textContent=value;
 byId(`windows-${id}-time`).textContent=`조회 시각: ${time}`;
}
function line(title,message){
 const section=document.createElement('section');
 const h=make('h3',title),p=make('p',message);
 section.append(h,p);
 details.append(section);
 return section;
}
function failPc(text) {
 for(const id of ['network','firewall','events']) card(id,`확인 불가 · ${text}`);
 details.replaceChildren(make('p',`PC 조회 확인 불가: ${text} 다음 조치: 로컬 서버 실행과 Windows 조회 권한·서비스를 확인한 후 「다시 조회」를 누르세요. 관리자 권한 상승은 요구하지 않습니다.`));
}

function eventLine(key,kind){
 if(kind?.status!=='ok')return `${key}: 확인 불가 · ${reason(kind)} 다음 조치: 이벤트 로그 서비스를 확인한 뒤 「다시 조회」를 누르세요. 0건으로 대체하지 않습니다.`;
 const mark=kind.limited?'최소 ':'';
 return `${key}: 최근 24시간 오류 ${mark}${kind.error}건 / 경고 ${mark}${kind.warning}건${kind.limited?' (조회 상한 5,000건 도달)':''}`;
}
function paintPc(data) {
 if(data?.schema!=='kimjh.windows-observation.v1'||data?.source!=='windows-read-only'||data?.windowHours!==24||
    !data.network||!data.firewall||!data.system||!data.application)throw Error('SCHEMA_UNVERIFIED');
 details.replaceChildren();
 const net=data.network, fw=data.firewall, system=data.system, application=data.application;
 if(net.status==='ok'&&Array.isArray(net.adapters)&&net.adapters.length>0){
   card('network',`IPv4 어댑터 ${net.adapters.length}개 확인`,fmtTime(net.observedAt));
   const netSection=line('로컬 네트워크 구성','IP 주소와 기본 게이트웨이는 이 PC에서 읽은 실제 값이며, 인터넷 연결이나 외부 SDP 연결 성공을 뜻하지 않습니다.');
   const list=document.createElement('ul');
   for(const item of net.adapters){list.append(make('li',`${item.name}: IPv4 ${item.ipv4} · 게이트웨이 ${item.gateway||'설정 없음'}`));}
   netSection.append(list);
 }else{
   card('network',`확인 불가 · ${reason(net)}`,fmtTime(net.observedAt));
   line('로컬 네트워크 구성',`확인 불가 · ${reason(net)} 다음 조치: 네트워크 어댑터 상태를 확인하고 「다시 조회」를 누르세요.`);
 }
 if(fw.status==='ok'&&Array.isArray(fw.profiles)&&fw.profiles.length>0){
   const disabled=fw.profiles.filter(x=>!x.enabled);
   card('firewall',disabled.length?`조회된 프로필 중 ${disabled.length}개 꺼짐`:'조회된 방화벽 프로필 켜짐',fmtTime(fw.observedAt));
   const section=line('Windows 방화벽 프로필','설정 읽기 전용. 이 화면은 방화벽을 켜거나 끄지 않으며, 프로필 상태가 보안을 보장하지 않습니다.');
   const list=document.createElement('ul');
   for(const x of fw.profiles)list.append(make('li',`${pname[x.name]||x.name}: ${x.enabled?'켜짐':'꺼짐'} · 기본 인바운드 ${actionName[x.inbound]||'확인 불가'} · 기본 아웃바운드 ${actionName[x.outbound]||'확인 불가'}`));
   section.append(list);
 }else{
   card('firewall',`확인 불가 · ${reason(fw)}`,fmtTime(fw.observedAt));
   line('Windows 방화벽 프로필',`확인 불가 · ${reason(fw)} 다음 조치: 일반 사용자 권한의 읽기 가능 여부를 확인하고 「다시 조회」를 누르세요. 설정은 변경하지 않습니다.`);
 }
 const both=system.status==='ok'&&application.status==='ok';
 if(both) {
   const totalErrors=system.error+application.error,totalWarnings=system.warning+application.warning;
   const capped=system.limited||application.limited;
   card('events',`24시간 오류 ${capped?'최소 ':''}${totalErrors}건 · 경고 ${capped?'최소 ':''}${totalWarnings}건${capped?' (상한 도달)':''}`,fmtTime(system.observedAt));
 }else{
   const missing=['System','Application'].filter(name=>(name==='System'?system:application).status!=='ok');
   card('events',`확인 불가 · ${missing.join('·')} 기록 조회 실패`,system.status==='ok'?fmtTime(system.observedAt):application.status==='ok'?fmtTime(application.observedAt):'확인 불가');
 }
 const logSection=line('최근 Windows 기록 (System · Application)','지난 24시간의 Warning(Level 3)·Error(Level 2) 이벤트 건수입니다. 침해·공격·악성코드 탐지 결과가 아닙니다.');
 logSection.append(make('p',eventLine('System',system)));
 logSection.append(make('p',`System 조회 시각: ${fmtTime(system.observedAt)}`));
 logSection.append(make('p',eventLine('Application',application)));
 logSection.append(make('p',`Application 조회 시각: ${fmtTime(application.observedAt)}`));
 history.unshift({at:fmtTime(new Date().toISOString()),system,application});
 if(history.length>6)history.pop();
 historyBody.replaceChildren();
 for(const sample of history){
   const tr=document.createElement('tr');
   for(const val of [sample.at,eventCell(sample.system,'error'),eventCell(sample.system,'warning'),
       eventCell(sample.application,'error'),eventCell(sample.application,'warning')])tr.append(make('td',val));
   historyBody.append(tr);
 }
}
function eventCell(item,kind){
 return item?.status==='ok'?`${item.limited?'≥ ':''}${item[kind]}건`:'확인 불가';
}
async function fetchJson(url,signal){
 const res=await fetch(url,{method:'GET',credentials:'same-origin',cache:'no-store',signal});
 if(!res.ok)throw Error('HTTP_UNAVAILABLE');
 const data=await res.json();
 if(data?.ok!==true)throw Error('API_FAILED');
 return data;
}
async function readSdp(signal){
 try{
   const r=await fetchJson('/api/diagnostics',signal);
   const mode=r.data?.engine?.mode,code=r.data?.engine?.code;
   const at=fmtTime(r.data?.checkedAt);
   if(mode==='disconnected'&&code==='ENGINE_NOT_CONNECTED'){
     card('sdp','SDP 미연결 · PC 조회와 별개',at);
   }else if(mode==='demo'&&code==='DEMO_ONLY'){
     card('sdp','예제(demo) 모드 · 실제 SDP 미연결',at);
   }else if(mode==='connected'&&code==='ADAPTER_CONFIGURED'){
     card('sdp','SDP 어댑터 구성됨 · 실데이터 조회 성공은 미확인',at);
   }else card('sdp','SDP 확인 불가 · 연결 상태 검증 필요',at);
 }catch{card('sdp','SDP 확인 불가 · 진단 API 읽기 실패. 다음 조치: 로컬 서버를 확인한 뒤 「다시 조회」를 누르세요.');}
}
if(measure&&state&&details&&historyBody&&ids.every(id=>byId(`windows-${id}-summary`)&&byId(`windows-${id}-time`))){
 // 네이티브 버튼을 유지해 Tab·Enter·Space 입력을 지원한다.
 const readyLabel = '다시 조회 · 관제 상태';
 measure.textContent = readyLabel;
 measure.addEventListener('click',async()=>{
   if(running)return;
   running=true;measure.disabled=true;
   measure.textContent='조회 중…';
   state.setAttribute('aria-busy','true');
   state.textContent='로컬 네트워크·방화벽·Windows 기록과 SDP를 각각 조회 중입니다. 이전 값은 현재 조회 결과가 아닙니다.';
   for(const id of ids)card(id,'조회 중 · 새 결과 대기','확인 중');
   details.replaceChildren(make('p','조회 중 · 새로운 Windows 조회 결과를 기다리고 있습니다. 과거 조회 이력은 아래 표에 별도로 남습니다.'));
   const controller=new AbortController(),timeout=setTimeout(()=>controller.abort(),14500);
   try{
     // 두 원천은 독립 상태: Windows 조회가 성공해도 SDP 연결 성공으로 계산하지 않는다.
     const [pcResult,sdpResult]=await Promise.allSettled([
       fetchJson('/api/windows-observation',controller.signal),
       readSdp(controller.signal),
     ]);
     if(pcResult.status==='fulfilled'){
       try{paintPc(pcResult.value.data);}catch{failPc('서버 측정 데이터 형식이 일치하지 않습니다.');}
     }else failPc('로컬 조회 API가 응답하지 않았습니다. 권한·서비스·서버 상태를 확인하세요.');
     if(sdpResult.status==='rejected')card('sdp','SDP 확인 불가 · 진단 실행 실패. 다음 조치: 로컬 서버 연결을 확인한 뒤 「다시 조회」를 누르세요.');
     state.textContent=pcResult.status==='fulfilled'
       ? '조회 종료 · 정상 응답 항목만 실측으로 표시합니다. 확인 불가 항목은 각각 이유와 다음 조치를 확인하세요. Windows 기록 건수는 침해·공격 탐지가 아닙니다.'
       : 'PC 조회 실패 · 네트워크·방화벽·기록의 현재 값을 확인할 수 없습니다. 로컬 서버를 확인한 뒤 「다시 조회」를 누르세요. SDP 상태는 별도입니다.';
   }finally{
     clearTimeout(timeout);
     running=false;measure.disabled=false;measure.textContent=readyLabel;
     state.setAttribute('aria-busy','false');
   }
 });
}
