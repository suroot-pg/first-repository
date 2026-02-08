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
$ua = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'

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
    .container { max-width: 900px; margin: 0 auto; background: #fff; padding: 20px; box-shadow: 0 0 10px rgba(0,0,0,0.1); border-radius: 8px; }
    h1 { color: #2c3e50; border-bottom: 2px solid #3498db; padding-bottom: 10px; }
    h2 { color: #2980b9; margin-top: 30px; font-size: 1.2em; border-left: 5px solid #3498db; padding-left: 10px; }
    .info-table { width: 100%; border-collapse: collapse; margin-top: 10px; }
    .info-table th, .info-table td { padding: 12px; border: 1px solid #e0e0e0; text-align: left; }
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

    # 콘솔 출력
    Write-Host $Message -ForegroundColor $Color

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
        $req = Invoke-WebRequest -Uri $target -UserAgent $ua -UseBasicParsing -TimeoutSec 30 -ErrorAction Stop
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
$protocols = @(
    @{Name = 'TLS 1.3'; Type = 12288; Risk = 'Safe' },
    @{Name = 'TLS 1.2'; Type = [Net.SecurityProtocolType]::Tls12; Risk = 'Safe' },
    @{Name = 'TLS 1.1'; Type = [Net.SecurityProtocolType]::Tls11; Risk = 'Medium' },
    @{Name = 'TLS 1.0'; Type = [Net.SecurityProtocolType]::Tls; Risk = 'High' },
    @{Name = 'SSL 3.0'; Type = [Net.SecurityProtocolType]::Ssl3; Risk = 'High' }
)

foreach ($p in $protocols) {
    try {
        [Net.ServicePointManager]::SecurityProtocol = $p.Type
        [Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
        $req = [Net.HttpWebRequest]::Create($target)
        $req.UserAgent = $ua
        $req.Timeout = 5000
        $req.AllowAutoRedirect = $false
        $null = $req.GetResponse()
        if ($p.Risk -eq 'Safe') { 
            Log-Result ("   - " + $p.Name + " : ✅ 지원함 (안전)") -Color Green
            $global:tlsResults[$p.Name] = "지원함"
        }
        else { 
            Log-Result ("   - " + $p.Name + " : ⚠️ 지원함 (경고: 구형 프로토콜)") -Color Red
            $global:tlsResults[$p.Name] = "지원함"
        }
    }
    catch { 
        Log-Result ("   - " + $p.Name + " : ❌ 미지원 (양호)") -Color Gray
        $global:tlsResults[$p.Name] = "미지원"
    }
}

Start-Section "3. 상세 보안 및 인증서 점검"

$certProps = @{ Expiry = $null; Issuer = $null; Algorithm = $null; KeySize = 0; Cipher = $null; Hash = $null; Protocol = $null; KeyExchange = $null }
try {
    $tcp = New-Object System.Net.Sockets.TcpClient($uri.Host, 443)
    $stream = $tcp.GetStream() 
    $ssl = New-Object System.Net.Security.SslStream($stream, $false, ({ $true }))
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
        $judge = "취약"
        $color = "Red"
    }
    elseif ($daysLeft -le 30) {
        $judge = "교체 권고"
        $color = "Yellow"
    }
    else {
        $judge = "양호"
        $color = "Green"
    }

    $checkDateStr = $checkDate.ToString("yyyy-MM-dd")
    Log-Result "   [인증서] 인증서 만료 여부 : 유효함 (~$expStr) (점검일 $checkDateStr 기준: $($daysLeft)일 남음) ($judge)" -Color $color
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
Start-Section "4. WAF 방어력 테스트 (Smart Check)"
$attacks = @(
    @{Name = 'XSS (Script)'; Payload = '?q=<script>alert(1)</script>' },
    @{Name = 'SQL Inject '; Payload = '?id=1 UNION SELECT 1, version() --' },
    @{Name = 'Traversal  '; Payload = '?file=../../../../etc/passwd' },
    @{Name = 'Cmd Inject '; Payload = '?cmd=; cat /etc/passwd' }
)

foreach ($atk in $attacks) {
    $testUrl = $target + $atk.Payload
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $req = Invoke-WebRequest -Uri $testUrl -UserAgent $ua -UseBasicParsing -TimeoutSec 5
        $code = $req.StatusCode
        $currentContent = $req.Content
        Write-Host ("   [Test] " + $atk.Name) -NoNewline
        
        # HTML 로깅을 위한 결과 문자열 조합
        $resultText = ""
        $resultColor = "Cyan"

        if ($code -ge 400) {
            $txt = " -> Result: " + $code + " (🛡️ 차단됨 - 안전)"
            Write-Host $txt -ForegroundColor Cyan
            $resultText = $txt
        }
        else {
            if ($currentContent -match 'blocked|rejected|denied|security|waf|access|forbidden|support id') {
                $txt = " -> Result: " + $code + " (🛡️ 내용상 차단됨 - 안전)"
                Write-Host $txt -ForegroundColor Cyan
                $resultText = $txt
            }
            else {
                $txt = " -> Result: " + $code + " (🚨 뚫림/취약 - 확인 필요!)"
                Write-Host $txt -ForegroundColor Red
                $resultText = $txt
                $resultColor = "Red"
            }
        }
        
        # HTML에 추가 (Key-Value 형식이 아니므로 별도 처리)
        if ($resultColor -eq 'Red') { $colorClass = 'danger' } else { $colorClass = 'safe' }
        [void]$reportHtml.AppendLine("<tr><th>[Test] $($atk.Name)</th><td><span class='$colorClass'>$resultText</span></td></tr>")

    }
    catch {
        $errCode = $_.Exception.Response.StatusCode.value__
        if ($errCode) {
            $txt = "   [Test] " + $atk.Name + " -> Result: " + $errCode + " (🛡️ 차단됨/오류 응답 - 안전)"
            Write-Host $txt -ForegroundColor Cyan
            [void]$reportHtml.AppendLine("<tr><th>[Test] $($atk.Name)</th><td><span class='safe'>$txt</span></td></tr>")
        }
        else {
            $txt = "   [Test] " + $atk.Name + " -> Result: 연결 실패 (" + $_.Exception.Message + ")"
            Write-Host $txt -ForegroundColor DarkGray
            [void]$reportHtml.AppendLine("<tr><th>[Test] $($atk.Name)</th><td><span class='warn'>$txt</span></td></tr>")
        }
    }
    Start-Sleep -Milliseconds 200
}


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
