# KimJH 3일차: 로컬 Windows 읽기 전용 관측. 관리자 권한 상승·설정 변경 없음.
# 반환값은 공개 가능한 상태·건수로 제한하며 이벤트 본문, SID, MAC, 비밀을 반환하지 않는다.
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
$stamp = { (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ss.fffZ') }
$since = (Get-Date).AddHours(-24)
$out = [ordered]@{
  schema = 'kimjh.windows-observation.v1'
  source = 'windows-read-only'
  windowHours = 24
  network = [ordered]@{status='unavailable';reason='NETWORK_QUERY_UNAVAILABLE';observedAt=(& $stamp)}
  firewall = [ordered]@{status='unavailable';reason='FIREWALL_QUERY_UNAVAILABLE';observedAt=(& $stamp)}
  system = [ordered]@{status='unavailable';reason='EVENT_LOG_UNAVAILABLE';observedAt=(& $stamp)}
  application = [ordered]@{status='unavailable';reason='EVENT_LOG_UNAVAILABLE';observedAt=(& $stamp)}
}
try {
  $adapters = @()
  foreach ($item in @(Get-NetIPConfiguration -ErrorAction Stop)) {
    $ips = @($item.IPv4Address | Where-Object { $_ -and $_.IPAddress -and $_.IPAddress -notlike '127.*' })
    if ($ips.Count -eq 0) { continue }
    $gateway = @($item.IPv4DefaultGateway | Where-Object { $_ -and $_.NextHop } | Select-Object -First 1)
    $adapters += [ordered]@{
      name = [string]$item.InterfaceAlias
      ipv4 = [string]$ips[0].IPAddress
      gateway = $(if ($gateway.Count -gt 0) { [string]$gateway[0].NextHop } else { '' })
    }
    if ($adapters.Count -ge 8) { break }
  }
  if ($adapters.Count -eq 0) {
    $out.network = [ordered]@{status='unavailable';reason='NETWORK_NO_IPV4';observedAt=(& $stamp)}
  } else {
    $out.network = [ordered]@{status='ok';adapters=@($adapters);observedAt=(& $stamp)}
  }
} catch {
  $out.network = [ordered]@{status='unavailable';reason='NETWORK_QUERY_UNAVAILABLE';observedAt=(& $stamp)}
}
try {
  $profiles = @()
  foreach ($profile in @(Get-NetFirewallProfile -ErrorAction Stop)) {
    if ([string]$profile.Name -notin @('Domain','Private','Public')) { continue }
    $profiles += [ordered]@{
      name = [string]$profile.Name
      enabled = [bool]$profile.Enabled
      inbound = [string]$profile.DefaultInboundAction
      outbound = [string]$profile.DefaultOutboundAction
    }
  }
  if ($profiles.Count -eq 0) {
    $out.firewall = [ordered]@{status='unavailable';reason='FIREWALL_PROFILES_UNAVAILABLE';observedAt=(& $stamp)}
  } else {
    $out.firewall = [ordered]@{status='ok';profiles=@($profiles);observedAt=(& $stamp)}
  }
} catch {
  $out.firewall = [ordered]@{status='unavailable';reason='FIREWALL_QUERY_UNAVAILABLE';observedAt=(& $stamp)}
}
function Read-LogCounts([string]$name) {
  $at = & $stamp
  try {
    # 5001개까지만 읽는다. 상한을 넘으면 정확한 총계가 아니라 최소 건수임을 표시한다.
    $events = @(Get-WinEvent -FilterHashtable @{LogName=$name;StartTime=$since;Level=@(2,3)} -MaxEvents 5001 -ErrorAction Stop)
    $limited = $events.Count -gt 5000
    if ($limited) { $events = @($events | Select-Object -First 5000) }
    $errors = @($events | Where-Object { $_.Level -eq 2 }).Count
    $warnings = @($events | Where-Object { $_.Level -eq 3 }).Count
    return [ordered]@{status='ok';error=$errors;warning=$warnings;limited=[bool]$limited;observedAt=(& $stamp)}
  } catch {
    # Windows가 "해당 시간대에 이벤트 없음"을 명시한 경우만 0건으로 기록한다.
    if ([string]$_.FullyQualifiedErrorId -match '^NoMatchingEventsFound') {
      return [ordered]@{status='ok';error=0;warning=0;limited=$false;observedAt=(& $stamp)}
    }
    return [ordered]@{status='unavailable';reason='EVENT_LOG_UNAVAILABLE';observedAt=(& $stamp)}
  }
}
$out.system = Read-LogCounts 'System'
$out.application = Read-LogCounts 'Application'
$out | ConvertTo-Json -Depth 8 -Compress
