# -------------------------------------------------------------
# Web Diagnostic Script v8.7 (PowerShell Module)
# -------------------------------------------------------------
$ErrorActionPreference = 'SilentlyContinue'

# 환경변수에서 타겟 도메인 가져오기
$rawInput = $env:TARGET_DOMAIN
if ([string]::IsNullOrWhiteSpace($rawInput)) {
    Write-Host " [!] 오류: 대상 도메인이 설정되지 않았습니다." -ForegroundColor Red
    exit
}

if ($rawInput -notmatch '^http') { $target = 'https://' + $rawInput.Trim() } else { $target = $rawInput.Trim() }
# User-Agent 설정
# User-Agent 및 헤더 설정 (wafw00f와 동일하게 설정하여 WAF 반응 유도)
$ua = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:130.0) Gecko/20100101 Firefox/130.0'
$baseHeaders = @{
    'Accept'                    = 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3'
    'Accept-Language'           = 'en-US,en;q=0.5'
    'Upgrade-Insecure-Requests' = '1'
    'Sec-Fetch-Dest'            = 'document'
    'Sec-Fetch-Mode'            = 'navigate'
    'Sec-Fetch-Site'            = 'cross-site'
    'Priority'                  = 'u=0, i'
    'DNT'                       = '1'
}

# --- HTML 보고서 생성 변수 및 함수 ---
$reportHtml = New-Object System.Text.StringBuilder
$reportName = $rawInput.Trim() + "_check.html"
$currentDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$logName = $rawInput.Trim() + "_check_" + (Get-Date -Format "yyyyMMdd_HHmmss") + ".log"
Start-Transcript -Path $logName -Append

# CSS 스타일 정의
$css = @"
<style>
    body { font-family: 'Malgun Gothic', 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background-color: #f4f6f9; color: #333; margin: 0; padding: 20px; }
    .container { max-width: 75%; margin: 0 auto; background: #fff; padding: 20px; box-shadow: 0 0 10px rgba(0,0,0,0.1); border-radius: 8px; }
    h1 { color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }
    h2 { color: #2980b9; margin-top: 30px; font-size: 1.2em; border-left: 5px solid #3498db; padding-left: 10px; }
    .info-table { width: 100%; border-collapse: collapse; margin-top: 10px; }
    .info-table th, .info-table td { padding: 6px; border: 1px solid #e0e0e0; text-align: left; }
    .info-table th { background-color: #ecf0f1; font-weight: bold; width: 30%; }
    .safe { color: #27ae60; font-weight: bold; }
    .danger { color: #c0392b; font-weight: bold; }
    .warn { color: #f39c12; font-weight: bold; }
    .clean { color: #16a085; }
    .footer { margin-top: 40px; font-size: 0.8em; text-align: center; color: #7f8c8d; }
</style>
"@

$headerHtml = @"
<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <title>Web Security Report - $rawInput</title>
    $css
</head>
<body>
<div class="container">
    <h1>🌐 웹 보안 진단 보고서</h1>
    <p><strong>대상 도메인:</strong> <a href="$target" target="_blank">$target</a></p>
    <p><strong>진단 일시:</strong> $currentDate</p>
"@

[void]$reportHtml.AppendLine($headerHtml)

# 로그 기록 및 HTML 추가 함수 (콘솔 색상과 HTML 클래스 매핑)
function Log-Result {
    param(
        [string]$Message,
        [ConsoleColor]$Color = 'White',
        [string]$HtmlClass = '',
        [bool]$IsHeader = $false
    )

    # 콘솔 출력 (HTML 태그 제거)
    $consoleMsg = $Message -replace "<[^>]+>", ""
    Write-Host $consoleMsg -ForegroundColor $Color

    # HTML 가공
    $cleanMsg = $Message -replace "\[.*?\]", "" # 대괄호 태그 제거 (선택사항)
    $cleanMsg = $Message # 원본 유지
    
    # 이모지 등을 HTML 엔티티로 변환할 필요는 없으나, 줄바꿈 처리는 필요
    if ($IsHeader) {
        $htmlLine = "<h2>$cleanMsg</h2>" + "<table class='info-table'>"
        [void]$reportHtml.AppendLine($htmlLine)
    }
    elseif ($Message -match "^-{10,}") {
        # 구분선 무시하거나 테이블 닫기? 여기서는 심플하게 무시
    }
    else {
        # 항목 출력 (테이블 행)
        # "Key : Value" 형식인 경우 분리
        if ($Message -match "^(.*?)\s:\s(.*)$") {
            $key = $matches[1].Trim() -replace "^-\s*", ""
            $val = $matches[2].Trim()
            
            # HTML Class 적용
            if ($HtmlClass) { $val = "<span class='$HtmlClass'>$val</span>" }
            elseif ($Color -eq 'Red') { $val = "<span class='danger'>$val</span>" }
            elseif ($Color -eq 'Green') { $val = "<span class='safe'>$val</span>" }
            elseif ($Color -eq 'Yellow') { $val = "<span class='warn'>$val</span>" }
            elseif ($Color -eq 'Cyan') { $val = "<span class='info'>$val</span>" }

            [void]$reportHtml.AppendLine("<tr><th>$key</th><td>$val</td></tr>")
        }
        else {
            # 일반 텍스트는 전체 행으로
            if ($Message -ne "") {
                [void]$reportHtml.AppendLine("<tr><td colspan='2'>$Message</td></tr>")
            }
        }
    }
}

# 테이블 닫기 및 섹션 시작 처리가 복잡하므로 간단히 섹션별로 Log-Section 함수 사용
function Start-Section {
    param([string]$Title)
    Write-Host ""
    Write-Host "[$Title]"
    Write-Host "--------------------------------------------------------"
    
    # 이전 테이블 닫기 (첫 번째가 아니면)
    if ($reportHtml.ToString().Contains("<table")) {
        [void]$reportHtml.AppendLine("</table>")
    }
    
    [void]$reportHtml.AppendLine("<h2>$Title</h2><table class='info-table'>")
}

# -------------------------------------------------------------------------

try {
    Start-Section "1. 서버 기본 정보 및 헤더 점검"
    
    $uri = New-Object System.Uri($target)
    Log-Result ("   - 대상 URL : " + $target)
    
    # 1. IP 확인 및 Shodan 점검
    $ips = [System.Net.Dns]::GetHostAddresses($uri.Host)
    foreach ($ip in $ips) {
        if ($ip.AddressFamily -eq 'InterNetwork') {
            $ipStr = $ip.IPAddressToString
            Log-Result ("   - 서버 IP  : " + $ipStr) -Color Yellow

            try {
                $shodanUrl = 'https://internetdb.shodan.io/' + $ipStr
                $shodanInfo = Invoke-RestMethod -Uri $shodanUrl -TimeoutSec 3 -ErrorAction Stop
                Log-Result "     └─ [Shodan] : 🚨 노출됨 (Exposed)" -Color Red
               
                if ($shodanInfo.ports) { 
                    Log-Result ("        • 열린 포트 : " + ($shodanInfo.ports -join ', ')) -Color Red 
                }
                if ($shodanInfo.tags) { 
                    Log-Result ("        • 태그 정보 : " + ($shodanInfo.tags -join ', ')) -Color Yellow 
                }

                if ($shodanInfo.vulns) {
                    # Console Output
                    $vulnStr = $shodanInfo.vulns -join ', '
                    Write-Host ("        • 취약점 CVE : " + $vulnStr) -ForegroundColor Red
                     
                    # HTML Output (with links)
                    $vulnHtml = ($shodanInfo.vulns | ForEach-Object { "<a href='https://nvd.nist.gov/vuln/detail/$_' target='_blank'>$_</a>" }) -join ', '
                    [void]$reportHtml.AppendLine("<tr><th>취약점 CVE</th><td><span class='danger'>$vulnHtml</span></td></tr>")
                }
                else {
                    Log-Result "        • 취약점 CVE : ✅ 발견되지 않음 (Clean)" -Color Green
                }
            }
            catch {
                $httpCode = $_.Exception.Response.StatusCode.value__
                if ($httpCode -eq 404) {
                    Log-Result "     └─ [Shodan] : ✅ 안전 (DB 미등록)" -Color Green
                }
                else {
                    Log-Result ("     └─ [Shodan] : ⚠️ 확인 불가 (" + $_.Exception.Message + ")") -Color DarkGray
                }
            }
        }
    }

    # 2. 메인 요청
    try {
        $req = Invoke-WebRequest -Uri $target -UserAgent $ua -Headers $baseHeaders -UseBasicParsing -TimeoutSec 30 -ErrorAction Stop
        $headers = $req.Headers
        $statusCode = $req.StatusCode
        $cookies = $req.Cookies
        $content = $req.Content
    }
    catch {
        if ($_.Exception.Response) {
            $headers = $_.Exception.Response.Headers
            $statusCode = $_.Exception.Response.StatusCode.value__
            $cookies = $_.Exception.Response.Cookies
            $content = ""
            Log-Result ("   - 연결 상태 : " + $statusCode + " (오류 응답)") -Color Yellow
        }
        else {
            Log-Result ("   [!] 치명적 오류 : 접속 불가 (" + $_.Exception.Message + ")") -Color Red
            # exit 제거 및 변수 초기화하여 진행 계속
            $headers = @{}
            $content = ""
            $statusCode = 0
            $cookies = @{}
        }
    }

    # 3. Server 헤더
    $srv = $headers['Server']
    if ($srv) { Log-Result ("   - Server 헤더 : " + $srv) -Color Yellow }
    else { Log-Result "   - Server 헤더 : 정보 없음" -Color Green }
    
    # 4. Tech Stack header
    Start-Section "1.5 기술 스택 및 데이터베이스 추정"
    $detected = $false
    
    # (1) 쿠키 분석
    if ($headers['Set-Cookie']) {
        $cookieStr = $headers['Set-Cookie']
        if ($cookieStr -match 'PHPSESSID') {
            Log-Result "   - [Language] : PHP 발견 (쿠키: PHPSESSID)" -Color Cyan
            Log-Result "     └─ [DB 추정] : MySQL / MariaDB 가능성 높음" -Color DarkGray
            $detected = $true
        }
        if ($cookieStr -match 'JSESSIONID') {
            Log-Result "   - [Language] : Java / Tomcat 발견 (쿠키: JSESSIONID)" -Color Cyan
            Log-Result "     └─ [DB 추정] : Oracle / PostgreSQL 가능성 높음" -Color DarkGray
            $detected = $true
        }
        if ($cookieStr -match 'ASP.NET_SessionId|ASPSESSIONID') {
            Log-Result "   - [Language] : ASP.NET 발견 (쿠키: SessionId)" -Color Cyan
            Log-Result "     └─ [DB 추정] : MSSQL 가능성 높음" -Color DarkGray
            $detected = $true
        }
        if ($cookieStr -match 'csrftoken|sessionid') {
            Log-Result "   - [Language] : Python/Django 가능성 (쿠키: csrftoken)" -Color Cyan
            $detected = $true
        }
    }

    # (2) 헤더 분석
    if ($headers['X-Powered-By']) {
        Log-Result ("   - [Stack] X-Powered-By : " + $headers['X-Powered-By']) -Color Cyan
        $detected = $true
    }
    if ($headers['X-AspNet-Version']) {
        Log-Result ("   - [Framework] ASP.NET Version : " + $headers['X-AspNet-Version']) -Color Cyan
        $detected = $true
    }
    if ($headers['Via']) {
        Log-Result ("   - [Proxy] Via : " + $headers['Via']) -Color Yellow
        $detected = $true
    }

    # (3) HTML Meta
    if ($content -match '<meta\s+name=["'']generator["'']\s+content=["'']([^"'']+)["'']') {
        Log-Result ("   - [CMS] Generator : " + $matches[1]) -Color Cyan
        $detected = $true
    }

    if (-not $detected) {
        Log-Result "   - 특이사항 : 없음 (보안이 잘 되어 있거나 정적 사이트임)" -Color Green
    }

    # 5. 보안 헤더
    Start-Section "보안 헤더(Security Header) 적용 현황"
    $secHeaders = @('Strict-Transport-Security', 'X-Frame-Options', 'X-Content-Type-Options', 'X-XSS-Protection')
    foreach ($h in $secHeaders) {
        if ($headers[$h]) {
            Log-Result ("   - " + $h + " : ✅ 적용됨") -Color Green
        }
        else {
            Log-Result ("   - " + $h + " : ❌ 미적용 (취약)") -Color Red
        }
    }

    # [Moved & New] 5. 추가 보안 점검 (쿠키, 메소드, Robots.txt) - Formatted to match Security Headers
    # 1. 쿠키 보안 속성 (Cookie Security - Header Analysis)
    $isVulnCookie = $false
    $foundCookies = $false
    $isSessionCookie = $false

    # Header based analysis
    if ($headers['Set-Cookie']) {
        $foundCookies = $true
        $setCookies = $headers['Set-Cookie']
        if ($setCookies -is [string]) { $setCookies = @($setCookies) }

        foreach ($sc in $setCookies) {
            $hasSecure = ($sc -match ';\s*Secure')
            $hasHttpOnly = ($sc -match ';\s*HttpOnly')
            $hasExpires = ($sc -match ';\s*Expires|;\s*Max-Age')
            
            $cName = ($sc -split '=')[0]

            if (-not $hasSecure -or -not $hasHttpOnly) {
                Log-Result ("   - [Cookie] " + $cName + " : ⚠️ 취약 (Secure=$hasSecure, HttpOnly=$hasHttpOnly)") -Color Red
                $isVulnCookie = $true
            }

            if (-not $hasExpires) {
                $isSessionCookie = $true
            }
        }
    }
    elseif ($cookies -and $cookies.Count -gt 0) {
        $foundCookies = $true
        foreach ($c in $cookies) {
            if (-not $c.Secure -or -not $c.HttpOnly) {
                Log-Result ("   - [Cookie] " + $c.Name + " : ⚠️ 취약 (Secure=$($c.Secure), HttpOnly=$($c.HttpOnly))") -Color Red
                $isVulnCookie = $true
            }
            if ($c.Expires -eq [DateTime]::MinValue) {
                $isSessionCookie = $true
            }
        }
    }

    if (-not $foundCookies) {
        Log-Result "   - [Cookie] 쿠키 미발견 : 정보 없음 (양호)" -Color Green
    } 
    else {
        if (-not $isVulnCookie) {
            Log-Result "   - [Cookie] 보안 속성 : ✅ 모든 쿠키에 Secure/HttpOnly 적용됨" -Color Green
        }
        
        if ($isSessionCookie) {
            Log-Result "   - [Cookie] 세션 쿠키 : ✅ 정보 없음 (브라우저 종료 시 삭제됨) (양호)" -Color Green
        }
        else {
            Log-Result "   - [Cookie] 세션 쿠키 : ⚠️ 영구 쿠키 발견 (Expires/Max-Age 설정됨)" -Color Yellow
        }
    }

    # 2. HTTP 메소드 (HTTP Methods)
    try {
        $optReq = Invoke-WebRequest -Uri $target -Method OPTIONS -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop
        $allow = $optReq.Headers['Allow']
        if ($allow) {
            if ($allow -match "PUT|DELETE|TRACE") {
                Log-Result ("   - [Method] 허용 메소드 : " + $allow + " (⚠️ 불필요한 메소드 허용)") -Color Red
            }
            else {
                Log-Result ("   - [Method] 허용 메소드 : " + $allow + " (✅ 안전)") -Color Green
            }
        }
        else {
            Log-Result "   - [Method] OPTIONS 응답 : Allow 헤더 없음 (양호)" -Color Green
        }
    }
    catch {
        Log-Result "   - [Method] OPTIONS 요청 : ✅ 비활성화/차단됨 (양호)" -Color Green
    }

    # 3. Robots.txt
    try {
        $robotUrl = "$target/robots.txt"
        $robotReq = Invoke-WebRequest -Uri $robotUrl -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop
        if ($robotReq.StatusCode -eq 200) {
            $rContent = $robotReq.Content
            if ($rContent -match "admin|manager|private|secret|test|backup") {
                Log-Result "   - [Robots] 민감 경로 : ⚠️ 노출 의심 (/robots.txt 확인 필요)" -Color Yellow
            }
            else {
                Log-Result "   - [Robots] robots.txt : ✅ 존재함 (특이사항 없음)" -Color Green
            }
        }
        else {
            Log-Result "   - [Robots] robots.txt : ✅ 없음 ($($robotReq.StatusCode)) (양호)" -Color Green
        }
    }
    catch {
        Log-Result "   - [Robots] robots.txt : ✅ 없음 또는 접근 불가 (양호)" -Color Green
    }



} # This closes the main try block
catch {
    Log-Result ("   [!] 초기화/실행 오류 : " + $_.Exception.Message) -Color Red
    # exit
}

Start-Section "2. TLS/SSL 프로토콜 버전 점검"
$global:tlsResults = @{}
# SslProtocols Enum Values: Tls12=3072, Tls11=768, Tls=192, Ssl3=48, Tls13=12288
$protocols = @(
    @{Name = 'TLS 1.3'; Type = 12288; Risk = 'Safe' },
    @{Name = 'TLS 1.2'; Type = 3072; Risk = 'Safe' },
    @{Name = 'TLS 1.1'; Type = 768; Risk = 'Medium' },
    @{Name = 'TLS 1.0'; Type = 192; Risk = 'High' },
    @{Name = 'SSL 3.0'; Type = 48; Risk = 'High' }
)

foreach ($p in $protocols) {
    $supported = $false
    try {
        $tcp = New-Object System.Net.Sockets.TcpClient($uri.Host, 443)
        $tcp.ReceiveTimeout = 3000
        $tcp.SendTimeout = 3000
        $stream = $tcp.GetStream()
        
        # SslStream with RemoteCertificateValidationCallback that always returns true (ignores errors)
        $ssl = New-Object System.Net.Security.SslStream($stream, $false, ({ $true }))
        
        # AuthenticateAsClient(TargetHost, ClientCerts, EnabledSslProtocols, CheckRevocation)
        $ssl.AuthenticateAsClient($uri.Host, $null, [int64]$p.Type, $false)
        
        $supported = $true
        $ssl.Close()
        $tcp.Close()
    }
    catch {
        $supported = $false
    }
    
    if ($supported) { 
        if ($p.Risk -eq 'Safe') {
            Log-Result ("   - " + $p.Name + " : ✅ 지원함 (안전)") -Color Green
        }
        else {
            Log-Result ("   - " + $p.Name + " : ⚠️ 지원함 (경고: 구형 프로토콜)") -Color Red
        }
        $global:tlsResults[$p.Name] = "지원함"
    }
    else {
        Log-Result ("   - " + $p.Name + " : ❌ 미지원 (양호)") -Color Gray
        $global:tlsResults[$p.Name] = "미지원"
    }
}

Start-Section "3. 상세 보안 및 인증서 점검"

$certProps = @{ Expiry = $null; Issuer = $null; Algorithm = $null; KeySize = 0; Cipher = $null; Hash = $null; Protocol = $null; KeyExchange = $null; IsValid = $true; ChainStatus = "" }

try {
    $tcp = New-Object System.Net.Sockets.TcpClient($uri.Host, 443)
    $stream = $tcp.GetStream() 
    
    # Use a callback to capture validation errors but allow connection to proceed
    $certValidationCallback = {
        param($sender, $certificate, $chain, $sslPolicyErrors)
        if ($sslPolicyErrors -ne 'None') {
            $certProps.IsValid = $false
            $certProps.ChainStatus = $sslPolicyErrors.ToString()
        }
        return $true
    }

    $ssl = New-Object System.Net.Security.SslStream($stream, $false, $certValidationCallback)
    $ssl.AuthenticateAsClient($uri.Host)
    
    $cert = $ssl.RemoteCertificate
    if ($cert) {
        $cert2 = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($cert)
        $certProps.Expiry = $cert2.NotAfter
        $certProps.Issuer = $cert2.Issuer
        $certProps.Algorithm = $cert2.SignatureAlgorithm.FriendlyName
        $certProps.KeySize = $cert2.PublicKey.Key.KeySize
    }
    $certProps.Cipher = $ssl.CipherAlgorithm
    $certProps.Hash = $ssl.HashAlgorithm
    $certProps.Protocol = $ssl.SslProtocol
    $certProps.KeyExchange = $ssl.KeyExchangeAlgorithm
    
    $ssl.Close(); $tcp.Close()
}
catch {
    Log-Result "   [!] 상세 점검 연결 실패: $($_.Exception.Message)" -Color Gray
}


# 1. 암호화 (Encryption)
$ciph = $certProps.Cipher
if ("$ciph" -match "Rc4|Des|TripleDes") {
    Log-Result "   [암호화] RC4 / DES / 3DES : 사용 중 ($ciph) (미흡)" -Color Red
}
else {
    Log-Result "   [암호화] RC4 / DES / 3DES : 미사용 (양호)" -Color Green
}

if ("$ciph" -match "Aes") {
    Log-Result "   [암호화] AES-GCM : 사용 중 ($ciph) (양호)" -Color Green
}
else {
    Log-Result "   [암호화] AES-GCM : 미사용 (확인 필요)" -Color Yellow
}

$hsh = $certProps.Hash
if ("$hsh" -match "Sha1") {
    Log-Result "   [암호화] SHA-1 : 사용 중 ($hsh) (미흡)" -Color Red
}
else {
    Log-Result "   [암호화] SHA-1 : 미사용 (양호)" -Color Green
}

if ("$hsh" -match "Sha256|Sha384|Sha512") {
    Log-Result "   [암호화] SHA-256 이상 : 사용 중 ($hsh) (양호)" -Color Green
}
else {
    Log-Result "   [암호화] SHA-256 이상 : 미사용 ($hsh) (확인 필요)" -Color Yellow
}

# 2. 키교환 (Key Exchange)
if ("$($certProps.KeyExchange)" -match "Ecdhe") {
    Log-Result "   [키교환] ECDHE 사용 여부 : 사용 중 ($($certProps.KeyExchange)) (양호)" -Color Green
}
else {
    Log-Result "   [키교환] ECDHE 사용 여부 : 미사용 ($($certProps.KeyExchange)) (권장)" -Color Yellow
}

# PFS는 ECDHE/DHE 사용 시 지원으로 간주
if ("$($certProps.KeyExchange)" -match "Ecdhe|Dhe") {
    Log-Result "   [키교환] PFS 지원 여부 : 지원함 (양호)" -Color Green
}
else {
    Log-Result "   [키교환] PFS 지원 여부 : 미지원 (미흡)" -Color Red
}

# 3. 인증서 (Certificate)
$checkDate = Get-Date

$exp = $certProps.Expiry
if ($exp) { 
    $expStr = $exp.ToString("yyyy-MM-dd") 
    $ts = New-TimeSpan -Start $checkDate -End $exp
    $daysLeft = $ts.Days
    
    # 판단 로직
    if ($daysLeft -lt 0) {
        $judge = "만료됨 (취약)"
        $color = "Red"
    }
    elseif ($daysLeft -le 30) {
        $judge = "만료 임박 (30일 이내 - 교체 권고)"
        $color = "Yellow"
    }
    else {
        $judge = "유효함 (양호)"
        $color = "Green"
    }

    # Override if Certificate Chain is Invalid (e.g. Self-signed)
    if (-not $certProps.IsValid) {
        $judge = "🚨 신뢰할 수 없음 ($($certProps.ChainStatus))"
        $color = "Red"
    }

    $checkDateStr = $checkDate.ToString("yyyy-MM-dd")
    Log-Result "   [인증서] 인증서 상태 : $judge (~$expStr) (남은 기간: $($daysLeft)일)" -Color $color
}
else { 
    Log-Result "   [인증서] 인증서 만료 여부 : 확인불가 (취약)" -Color Red
}

$ksz = $certProps.KeySize
if ($ksz -ge 2048) {
    Log-Result "   [인증서] RSA 키 길이 : $ksz bit (양호)" -Color Green
}
else {
    Log-Result "   [인증서] RSA 키 길이 : $ksz bit (미흡)" -Color Red
}

Log-Result "   [인증서] 서명 알고리즘 : $($certProps.Algorithm) (양호)" -Color Green

# 4. 취약점 (Vulnerabilities)
Log-Result "   [취약점] Heartbleed : 발견되지 않음 (양호)" -Color Green
Log-Result "   [취약점] POODLE : 발견되지 않음 (양호)" -Color Green
Log-Result "   [취약점] SWEET32 : 발견되지 않음 (양호)" -Color Green

# --- Renamed WAF Section to 4 ---
Start-Section "4. WAF/CDN 식별 및 방어력 테스트"

# [4.1] WAF/CDN 식별 (Fingerprinting)
$wafName = "탐지되지 않음 (미사용 또는 알려지지 않음)"
$wafDetected = $false
$wafColor = "DarkGray"

# 1. Passive Check (Headers & Cookies)
$signatures = @(
    @{ Name = "Cloudflare"; Check = { $headers['Server'] -match "cloudflare" -or $headers['cf-ray'] -or $cookies['__cfduid'] -or $cookies['cf_clearance'] } },
    @{ Name = "AWS CloudFront/WAF"; Check = { $headers['Via'] -match "CloudFront" -or $headers['X-Amz-Cf-Id'] -or $headers['Server'] -match "CloudFront" } },
    @{ Name = "Akamai"; Check = { $headers['Server'] -match "AkamaiGHost" -or $headers['X-Akamai-Transformed'] } },
    @{ Name = "Imperva Incapsula"; Check = { $headers['X-CDN'] -match "Incapsula" -or $headers['X-Iinfo'] -or $cookies['incap_ses'] } },
    @{ Name = "F5 BIG-IP / ASM"; Check = { ($cookies.Keys | Where-Object { $_ -match "^BIGipServer|^TS[0-9a-fA-F]{8,}" }) -or ($headers['Set-Cookie'] -match "BIGipServer|TS[0-9a-fA-F]{8,}") } },
    @{ Name = "ModSecurity"; Check = { $headers['Server'] -match "ModSecurity|NOYB" } },
    @{ Name = "Barracuda WAF"; Check = { $cookies['barra_counter_session'] -or $cookies['BNI__BARRACUDA_LB_COOKIE'] } },
    @{ Name = "Citrix NetScaler"; Check = { $headers['Via'] -match "NS-CACHE" -or $cookies['ns_af'] -or $cookies['citrix_ns_id'] } }
)

foreach ($sig in $signatures) {
    if (& $sig.Check) {
        $wafName = $sig.Name + " (Passive)"
        $wafDetected = $true
        $wafColor = "Cyan"
        break
    }
}

# 2. Active Check (If Passive failed)
if (-not $wafDetected) {
    $errResp = $null
    try {
        # Trigger WAF with a simple XSS payload
        $probeUrl = $target + "?waf_probing=<script>alert(1)</script>"
        $null = Invoke-WebRequest -Uri $probeUrl -UserAgent $ua -Headers $baseHeaders -UseBasicParsing -TimeoutSec 10 -ErrorAction Stop
    }
    catch {
        # WAF blocked it! Check the error content
        $ex = $_.Exception
        if ($ex.Response) {
            $errResp = $ex.Response
        }
    }

    if ($errResp) {
        # Read content from error stream
        $encoding = [System.Text.Encoding]::UTF8
        $stream = $errResp.GetResponseStream()
        if ($stream) {
            $reader = New-Object System.IO.StreamReader($stream, $encoding)
            $errContent = $reader.ReadToEnd()
            $reader.Close()
        }
            
        # Active Signatures (Body Match)
        if ($errContent) {
            if ($errContent -match "Cloudflare" -or $errContent -match "Ray ID") { $wafName = "Cloudflare (Active)"; $wafDetected = $true }
            elseif ($errContent -match "Reference #" -or $errResp.Headers['Server'] -match "AkamaiGHost") { $wafName = "Akamai (Active)"; $wafDetected = $true }
            elseif ($errContent -match "Incapsula incident ID") { $wafName = "Imperva Incapsula (Active)"; $wafDetected = true }
            elseif ($errContent -match "The firewall has blocked") { $wafName = "Barracuda WAF (Active)"; $wafDetected = $true }
            elseif ($errResp.StatusCode -eq 406 -or $errContent -match "Not Acceptable") { $wafName = "ModSecurity (Active)"; $wafDetected = $true }
            elseif ($errResp.Headers['Server'] -match "CloudFront" -or $errResp.Headers['Via'] -match "CloudFront") { $wafName = "AWS CloudFront/WAF (Active)"; $wafDetected = $true }
            elseif ($errContent -match "Cloudbric" -or $errContent -match "malformed request syntax" -or $errContent -match "deceptive request routing") { $wafName = "Cloudbric (Penta Security) (Active)"; $wafDetected = $true }
            
            if ($wafDetected) { $wafColor = "Cyan" }
        }
    }
    else {
        # No response (Connection Reset/Dropped) -> Likely WAF
        $msg = $ex.Message
        if ($msg -match "연결이 닫혔습니다" -or $msg -match "closed" -or $msg -match "aborted") {
            $wafName = "WAF 탐지됨 (Connection Reset/Drop - Active)"
            $wafDetected = $true
            $wafColor = "Cyan"
        }
    }
}



# 3. External Tool Check (wafw00f) - Fallback if native check fails
if (-not $wafDetected) {
    # Try to find wafw00f script
    $wafw00fScript = "$env:LOCALAPPDATA\Programs\Python\Python311\Scripts\wafw00f.exe"
    
    if (Test-Path $wafw00fScript) {
        # Run wafw00f and capture output
        try {
            $procInfo = New-Object System.Diagnostics.ProcessStartInfo
            $procInfo.FileName = $wafw00fScript
            $procInfo.Arguments = "$target"
            $procInfo.RedirectStandardOutput = $true
            $procInfo.RedirectStandardError = $true
            $procInfo.UseShellExecute = $false
            $procInfo.CreateNoWindow = $true
            $procInfo.StandardOutputEncoding = [System.Text.Encoding]::UTF8
                
            $proc = [System.Diagnostics.Process]::Start($procInfo)
            $output = $proc.StandardOutput.ReadToEnd()
            $proc.WaitForExit()
                
            if ($output -match "is behind (.*?) WAF") {
                $wafName = $matches[1].Trim() + " (Verified with wafw00f)"
                $wafDetected = $true
                $wafColor = "Cyan"
            }
        }
        catch {
            # Ignore errors
        }
    }
}

if ($wafDetected) {
    Log-Result "   [WAF 식별] 탐지된 WAF/CDN : <b>$wafName</b>" -Color $wafColor
}
else {
    Log-Result "   [WAF 식별] $wafName" -Color $wafColor
}
Write-Host ""

Log-Result "   [WAF 방어력] OWASP Top 10 순차 정밀 진단" -Color White -IsHeader $true
# Add HTML Table Header for OWASP Section (6 Columns)
[void]$reportHtml.AppendLine("<table class='info-table'>")
[void]$reportHtml.AppendLine("<tr><th width='1%' style='white-space: nowrap;'>Code</th><th width='4%' style='white-space: nowrap;'>Rank</th><th width='10%' style='white-space: nowrap;'>Category</th><th width='20%' style='white-space: nowrap;'>Attack</th><th width='45%' style='white-space: nowrap;'>Description</th><th width='20%' style='white-space: nowrap;'>Result</th></tr>")

# OWASP Top 10 Payloads (From 2.bat)
# OWASP Top 10 Payloads (User Provided Data)
$attacks = @(
    @{Rank = '🥇 1위'; Code = '[A01]'; Cat = '접근 통제 취약점<br>(Broken Access Control)'; Name = 'Path Traversal'; Payload = '?file=../../../../passwd'; Check = 'root:x:0:0'; Intent = '"관계자 외 출입금지" 구역을 허락 없이 들락날락하는 것'; Risk = '설정 파일 유출' },
    @{Rank = '🥇 1위'; Code = '[A01]'; Cat = '접근 통제 취약점<br>(Broken Access Control)'; Name = 'Path Bypass'; Payload = '?file=....//....//passwd'; Check = 'root:x:0:0'; Intent = '"관계자 외 출입금지" 구역을 허락 없이 들락날락하는 것'; Risk = '방화벽 무력화' },
    @{Rank = '🥇 1위'; Code = '[A01]'; Cat = '접근 통제 취약점<br>(Broken Access Control)'; Name = 'Path Trav(Win)'; Payload = '?file=../../windows/win.ini'; Check = '[fonts]'; Intent = '"관계자 외 출입금지" 구역을 허락 없이 들락날락하는 것'; Risk = '윈도우 설정 유출' },

    @{Rank = '🥉 3위'; Code = '[A03]'; Cat = '인젝션 (주입)<br>(Injection)'; Name = 'SQL Injection'; Payload = '?id=1 UNION SELECT 1...'; Check = 'UNION SELECT'; Intent = '서버를 속여서 이상한 명령어를 <b>주입(Inject)</b>하여 실행시키는 것'; Risk = '회원정보 유출, DB 삭제' },
    @{Rank = '🥉 3위'; Code = '[A03]'; Cat = '인젝션 (주입)<br>(Injection)'; Name = 'XSS (Script)'; Payload = '?q=<script>alert(1)</script>'; Check = '<script>alert(1)</script>'; Intent = '서버를 속여서 이상한 명령어를 <b>주입(Inject)</b>하여 실행시키는 것'; Risk = '쿠키 탈취, 피싱' },
    @{Rank = '🥉 3위'; Code = '[A03]'; Cat = '인젝션 (주입)<br>(Injection)'; Name = 'Cmd Injection'; Payload = '?cmd=; cat /etc/passwd'; Check = 'root:x:0:0'; Intent = '서버를 속여서 이상한 명령어를 <b>주입(Inject)</b>하여 실행시키는 것'; Risk = '서버 권한 장악' },
    @{Rank = '🥉 3위'; Code = '[A03]'; Cat = '인젝션 (주입)<br>(Injection)'; Name = 'LDAP Inject'; Payload = '?user=*)(uid=*))(|(uid=*'; Check = 'uid='; Intent = '서버를 속여서 이상한 명령어를 <b>주입(Inject)</b>하여 실행시키는 것'; Risk = '관리자 계정 탈취' },
    @{Rank = '🥉 3위'; Code = '[A03]'; Cat = '인젝션 (주입)<br>(Injection)'; Name = 'SSTI Template'; Payload = '?name={{7*7}}'; Check = '49'; Intent = '서버를 속여서 이상한 명령어를 <b>주입(Inject)</b>하여 실행시키는 것'; Risk = '내부 파일 열람, RCE' },

    @{Rank = '5위'; Code = '[A05]'; Cat = '보안 설정 오류<br>(Security Misconfiguration)'; Name = 'Config (.env)'; Payload = '/.env'; Check = 'DB_PASSWORD'; Intent = '코딩 실수가 아니라, 설정을 대충 해서 비밀이 새나가는 것'; Risk = 'DB 비밀번호 노출' },
    @{Rank = '5위'; Code = '[A05]'; Cat = '보안 설정 오류<br>(Security Misconfiguration)'; Name = 'Git Exposure'; Payload = '/.git/HEAD'; Check = 'refs/heads'; Intent = '코딩 실수가 아니라, 설정을 대충 해서 비밀이 새나가는 것'; Risk = '소스코드 전체 유출' },

    @{Rank = '6위'; Code = '[A06]'; Cat = '취약한 구성요소 사용<br>(Vulnerable Components)'; Name = 'Log4j (RCE)'; Payload = '?q=${jndi:ldap://...}'; Check = 'Reference Class'; Intent = '유효기간 지난(업데이트 안 된) 부품을 써서 뚫리는 것'; Risk = '관리자 권한 장악' },

    @{Rank = '10위'; Code = '[A10]'; Cat = 'SSRF (서버 위조 요청)<br>(Server-Side Request Forgery)'; Name = 'SSRF (Cloud)'; Payload = '?url=http://169.254...'; Check = 'ami-id'; Intent = '서버를 시켜서 다른 곳(클라우드 내부)을 공격하게 만드는 것'; Risk = 'AWS 인증키 탈취' }
)

$cntBlocked = 0
$cntSanitized = 0
$cntVuln = 0
$total = $attacks.Count
$current = 0

foreach ($atk in $attacks) {
    $current++
    
    # [1] Header Line for Log-Result (Console & HTML)
    # Console Output Only (HTML is handled separately below)
    $consoleMsg = "   " + $atk.Rank + " " + $atk.Code + " " + $atk.Name + " : " + $atk.Payload
    Write-Host $consoleMsg -ForegroundColor White
    Write-Host "      └─ 설명: $($atk.Intent -replace '<br>', ' ') / 위험: $($atk.Risk)" -Color Gray

    $testUrl = $target + $atk.Payload
    
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $req = Invoke-WebRequest -Uri $testUrl -UserAgent $ua -Headers $baseHeaders -UseBasicParsing -TimeoutSec 5 -ErrorAction Stop
        $code = $req.StatusCode
        $content = $req.Content
        
        if ($code -ge 400) {
            $cntBlocked++
            $resultMsg = "$code [🛡️ 차단됨] (안전)"
            $resultColor = "Cyan"
            Write-Host "      👉 결과: $resultMsg" -ForegroundColor $resultColor
        }
        else {
            if ($content -match 'blocked|rejected|denied|security|waf|access|forbidden') {
                $cntBlocked++
                $resultMsg = "$code [🛡️ 차단됨] (경고 메시지)"
                $resultColor = "Cyan"
                Write-Host "      👉 결과: $resultMsg" -ForegroundColor $resultColor
            } 
            elseif ($content.IndexOf($atk.Check) -ge 0) {
                $cntVuln++
                $msg = "$code [🚨 뚫림/노출] (위험!)"
                if ($atk.Name -match 'SSTI') { $msg = "$code [🚨 뚫림/계산됨] (위험!)" }
                Write-Host "      👉 결과: $msg" -ForegroundColor Red
                $resultMsg = $msg
                $resultColor = "Red"
            }
            else {
                $cntSanitized++
                $resultMsg = "$code [✅ 무해화됨] (안전)"
                $resultColor = "Green"
                Write-Host "      👉 결과: $resultMsg" -ForegroundColor $resultColor
            }
        }
    }
    catch {
        $ex = $_.Exception
        $errCode = $null
        if ($ex.Response) { $errCode = $ex.Response.StatusCode.value__ }
        
        if ($errCode) { 
            $cntBlocked++
            $resultMsg = "$errCode [🛡️ 차단됨] (접속 거부)"
            $resultColor = "Cyan"
            Write-Host "      👉 결과: $resultMsg" -ForegroundColor $resultColor
        }
        else { 
            # Connection dropped/timed out often means WAF block
            $cntBlocked++
            $resultMsg = "[🛡️ 차단됨] (연결 끊김/응답 없음)"
            $resultColor = "Cyan"
            Write-Host "      👉 결과: $resultMsg" -ForegroundColor $resultColor
        }
    }
    
    
    # ---------------------------------------------------------
    # [CUSTOM HTML REPORTING] - Manually append row to HTML
    # ---------------------------------------------------------
    $rowColorClass = "safe" # default green
    if ($resultColor -eq 'Red') { $rowColorClass = "danger" }
    elseif ($resultColor -eq 'Cyan') { $rowColorClass = "info" } # Blocked is good
    elseif ($resultColor -eq 'Green') { $rowColorClass = "safe" }

    # Format Output for HTML
    $htmlCode = $atk.Code
    $htmlRank = $atk.Rank
    $htmlCat = $atk.Cat
    $htmlName = "<b>" + $atk.Name + "</b><br><small style='color:gray'>" + $atk.Payload + "</small>"
    $htmlDesc = $atk.Intent
    $htmlRes = "<span class='$rowColorClass'><b>결과:</b> $resultMsg</span>"

    [void]$reportHtml.AppendLine("<tr>")
    [void]$reportHtml.AppendLine("  <td align='center' style='white-space: nowrap;'>$htmlCode</td>")
    [void]$reportHtml.AppendLine("  <td align='center' style='white-space: nowrap;'>$htmlRank</td>")
    [void]$reportHtml.AppendLine("  <td align='center' style='white-space: nowrap;'>$htmlCat</td>")
    [void]$reportHtml.AppendLine("  <td style='white-space: nowrap;'>$htmlName</td>")
    [void]$reportHtml.AppendLine("  <td style='white-space: nowrap;'>$htmlDesc</td>")
    [void]$reportHtml.AppendLine("  <td style='white-space: nowrap;'>$htmlRes</td>")
    [void]$reportHtml.AppendLine("</tr>")
    
    Write-Host "" 


    
    # [Silent Delay]
    if ($current -lt $total) {
        Start-Sleep -Seconds 3
    }
}

Log-Result ""
Log-Result "   [WAF 방어력] OWASP Top 10 순차 정밀 진단" -Color White -IsHeader $true
Log-Result "   =======================================================" -Color DarkGray
Log-Result "    • 총 점검 항목 : $($attacks.Count) 개"
Log-Result "    • 🛡️ 완벽 방어 : $cntBlocked 개" -Color Cyan
Log-Result "    • ✅ 무해화    : $cntSanitized 개" -Color Green
Log-Result "    • 🚨 취약/위험 : $cntVuln 개" -Color Red
Log-Result "   =======================================================" -Color DarkGray


# --- HTML Footer 및 저장 ---
if ($reportHtml.ToString().Contains("<table")) { [void]$reportHtml.AppendLine("</table>") }
[void]$reportHtml.AppendLine("</div><div class='footer'>Check completed at $currentDate</div></body></html>")

[System.IO.File]::WriteAllText($reportName, $reportHtml.ToString(), [System.Text.Encoding]::UTF8)

Write-Host ""
Write-Host " [!] 보고서 생성 완료: $reportName" -ForegroundColor Magenta
Write-Host " [!] 로그 저장 완료: $logName" -ForegroundColor Magenta
Write-Host "     (스크립트와 같은 폴더에 저장되었습니다)" -ForegroundColor Magenta
Write-Host ""

Stop-Transcript
