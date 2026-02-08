@echo off
setlocal
:: [필수] 콘솔을 UTF-8 모드로 변경 (이모지 및 한글 출력용)
chcp 65001 >nul
title Web Security Scanner v8.6 (Enhanced Error Handling)

:MAIN_MENU
cls
echo.
echo ========================================================
echo   🛡️ 웹 종합 보안 진단 도구 v8.6 (오류 개선판)
echo ========================================================
echo.
echo   [안내] 진단할 대상 도메인을 입력하세요.
echo   (예: google.com)
echo.

set /p TARGET_INPUT="[입력] 주소 >> "
if "%TARGET_INPUT%"=="" goto MAIN_MENU

:: 입력값 환경변수 처리
set "TARGET_DOMAIN=%TARGET_INPUT%"

echo.
echo [1] 서버 기본 정보 및 헤더 점검
echo --------------------------------------------------------

powershell -NoProfile -ExecutionPolicy Bypass -Command ^
    "$ErrorActionPreference = 'SilentlyContinue'; "^
    "$rawInput = $env:TARGET_DOMAIN; "^
    "if ($rawInput -notmatch '^http') { $target = 'https://' + $rawInput.Trim() } else { $target = $rawInput.Trim() }; "^
    "$ua = 'Mozilla/5.0 (compatible; SecurityCheck/8.6)'; "^
    ""^
    "try { "^
    "    $uri = New-Object System.Uri($target); "^
    "    Write-Host ('   - 대상 URL : ' + $target); "^
    "    $ips = [System.Net.Dns]::GetHostAddresses($uri.Host); "^
    ""^
    "    foreach($ip in $ips){ "^
    "       if($ip.AddressFamily -eq 'InterNetwork'){ "^
    "           $ipStr = $ip.IPAddressToString; "^
    "           Write-Host ('   - 서버 IP  : ' + $ipStr) -ForegroundColor Yellow; "^
    ""^
    "           Write-Host '     └─ [Shodan] 노출 여부 확인 중...' -NoNewline; "^
    "           try { "^
    "               $shodanUrl = 'https://internetdb.shodan.io/' + $ipStr; "^
    "               $shodanInfo = Invoke-RestMethod -Uri $shodanUrl -TimeoutSec 3 -ErrorAction Stop; "^
    "               Write-Host ' 🚨 [위험] 노출됨 (Exposed)' -ForegroundColor Red; "^
    "               if($shodanInfo.ports) { Write-Host ('        • 열린 포트 : ' + ($shodanInfo.ports -join ', ')) -ForegroundColor Red }; "^
    "               if($shodanInfo.tags)  { Write-Host ('        • 태그 정보 : ' + ($shodanInfo.tags -join ', ')) -ForegroundColor Yellow }; "^
    "               if($shodanInfo.vulns) { "^
    "                   Write-Host ('        • 취약점 CVE: ' + ($shodanInfo.vulns -join ', ')) -ForegroundColor Red "^
    "               } else { "^
    "                   Write-Host '        • 취약점 CVE: ✅ 발견되지 않음 (Clean)' -ForegroundColor Green "^
    "               }; "^
    "           } catch { "^
    "               $httpCode = $_.Exception.Response.StatusCode.value__; "^
    "               if ($httpCode -eq 404) { "^
    "                   Write-Host ' ✅ 안전 (Shodan DB 미등록)' -ForegroundColor Green; "^
    "               } else { "^
    "                   Write-Host (' ⚠️ 확인 불가 (조회 실패: ' + $_.Exception.Message + ')') -ForegroundColor DarkGray; "^
    "               } "^
    "           } "^
    "       } "^
    "    }; "^
    ""^
    "    try { "^
    "        $req = Invoke-WebRequest -Uri $target -UserAgent $ua -UseBasicParsing -TimeoutSec 10 -ErrorAction Stop; "^
    "        $headers = $req.Headers; "^
    "        $statusCode = $req.StatusCode; "^
    "    } catch { "^
    "        if ($_.Exception.Response) { "^
    "            $headers = $_.Exception.Response.Headers; "^
    "            $statusCode = $_.Exception.Response.StatusCode.value__; "^
    "            Write-Host ('   - 연결 상태 : ' + $statusCode + ' (오류 응답이지만 헤더 분석 가능)') -ForegroundColor Yellow; "^
    "        } else { "^
    "            Write-Host ('   [!] 치명적 오류: 사이트에 접속할 수 없습니다. (' + $_.Exception.Message + ')') -ForegroundColor Red; "^
    "            exit; "^
    "        } "^
    "    } "^
    ""^
    "    $srv = $headers['Server']; "^
    "    if($srv){ "^
    "        if($srv -match '[0-9]\.'){ "^
    "            Write-Host ('   - Server 헤더 : ' + $srv + ' 🚨 경고: 버전 노출됨') -ForegroundColor Red "^
    "        } else { "^
    "            Write-Host ('   - Server 헤더 : ' + $srv + ' ✅ 양호 (버전 숨김)') -ForegroundColor Green "^
    "        } "^
    "    } else { "^
    "        Write-Host '   - Server 헤더 : ✅ 정보 없음 (매우 안전)' -ForegroundColor Green "^
    "    } "^
    ""^
    "    $xpw = $headers['X-Powered-By']; "^
    "    if($xpw){ "^
    "        Write-Host ('   - 기술 스택 노출: ' + $xpw + ' ⚠️ 경고: 불필요한 정보') -ForegroundColor Yellow "^
    "    } else { "^
    "        Write-Host '   - 기술 스택 노출: ✅ 정보 없음 (안전)' -ForegroundColor Green "^
    "    }; "^
    ""^
    "    Write-Host ''; "^
    "    Write-Host '   [보안 헤더(Security Header) 적용 현황]'; "^
    "    $secHeaders = @('Strict-Transport-Security', 'X-Frame-Options', 'X-Content-Type-Options', 'X-XSS-Protection'); "^
    "    foreach($h in $secHeaders){ "^
    "        if($headers.ContainsKey($h)){ "^
    "            Write-Host ('   - ' + $h + ' : ✅ 적용됨') -ForegroundColor Green "^
    "        } else { "^
    "            Write-Host ('   - ' + $h + ' : ❌ 미적용 (취약)') -ForegroundColor Red "^
    "        } "^
    "    } "^
    "} catch { Write-Host ('   [!] 초기화/DNS 오류 : ' + $_.Exception.Message) -ForegroundColor Red; exit }"^
    ""^
    "Write-Host ''; "^
    "Write-Host '[2] TLS/SSL 프로토콜 버전 점검'; "^
    "Write-Host '--------------------------------------------------------'; "^
    "$protocols = @( "^
    "    @{Name='SSL 3.0'; Type=[Net.SecurityProtocolType]::Ssl3; Risk='High'}, "^
    "    @{Name='TLS 1.0'; Type=[Net.SecurityProtocolType]::Tls;  Risk='High'}, "^
    "    @{Name='TLS 1.1'; Type=[Net.SecurityProtocolType]::Tls11; Risk='Medium'}, "^
    "    @{Name='TLS 1.2'; Type=[Net.SecurityProtocolType]::Tls12; Risk='Safe'}, "^
    "    @{Name='TLS 1.3'; Type=12288; Risk='Safe'} "^
    "); "^
    "foreach($p in $protocols){ "^
    "    try { "^
    "        [Net.ServicePointManager]::SecurityProtocol = $p.Type; "^
    "        $req = [Net.HttpWebRequest]::Create($target); "^
    "        $req.Timeout = 2000; "^
    "        $req.AllowAutoRedirect = $false; "^
    "        $null = $req.GetResponse(); "^
    "        if($p.Risk -eq 'Safe'){ Write-Host ('   - ' + $p.Name + ' : ✅ 지원함 (안전)') -ForegroundColor Green } "^
    "        else { Write-Host ('   - ' + $p.Name + ' : ⚠️ 지원함 (경고: 구형 프로토콜)') -ForegroundColor Red } "^
    "    } catch { Write-Host ('   - ' + $p.Name + ' : ❌ 미지원 (양호)') -ForegroundColor Gray } "^
    "}"^
    ""^
    "Write-Host ''; "^
    "Write-Host '[3] WAF 방어력 테스트 (Smart Check)'; "^
    "Write-Host '--------------------------------------------------------'; "^
    "$attacks = @( "^
    "    @{Name='XSS (Script)'; Payload='?q=<script>alert(1)</script>'}, "^
    "    @{Name='SQL Inject '; Payload='?id=1 UNION SELECT 1, version() --'}, "^
    "    @{Name='Traversal  '; Payload='?file=../../../../etc/passwd'}, "^
    "    @{Name='Cmd Inject '; Payload='?cmd=; cat /etc/passwd'} "^
    "); "^
    "foreach($atk in $attacks){ "^
    "    $testUrl = $target + $atk.Payload; "^
    "    try { "^
    "        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; "^
    "        $req = Invoke-WebRequest -Uri $testUrl -UserAgent $ua -UseBasicParsing -TimeoutSec 5; "^
    "        $code = $req.StatusCode; "^
    "        $content = $req.Content; "^
    "        Write-Host ('   [Test] ' + $atk.Name); "^
    "        if($code -ge 400){ "^
    "             Write-Host ('     Result: ' + $code + ' (🛡️ 차단됨 - 안전)') -ForegroundColor Cyan; "^
    "        } else { "^
    "             if($content -match 'blocked|rejected|denied|security|waf|access|forbidden|support id') { "^
    "                 Write-Host ('     Result: ' + $code + ' (🛡️ 내용상 차단됨 - 안전)') -ForegroundColor Cyan; "^
    "             } else { "^
    "                 Write-Host ('     Result: ' + $code + ' (🚨 뚫림/취약 - 확인 필요!)') -ForegroundColor Red; "^
    "             } "^
    "        } "^
    "    } catch { "^
    "        $errCode = $_.Exception.Response.StatusCode.value__; "^
    "        if($errCode){ "^
    "            Write-Host ('     Result: ' + $errCode + ' (🛡️ 차단됨/오류 응답 - 안전)') -ForegroundColor Cyan "^
    "        } else { "^
    "            Write-Host ('     Result: 연결 실패 (' + $_.Exception.Message + ')') -ForegroundColor DarkGray "^
    "        } "^
    "    } "^
    "    Start-Sleep -Milliseconds 200; "^
    "}"


echo.
echo ========================================================
echo.
echo   [?] 작업을 선택하세요.
echo   [R] 다시 테스트하기 (Retry)
echo   [X] 종료하기 (Exit)
echo.

set /p CHOICE="[선택] >> "
if /i "%CHOICE%"=="r" goto MAIN_MENU
if /i "%CHOICE%"=="x" goto EXIT_TOOL
goto MAIN_MENU

:EXIT_TOOL
echo.
echo 프로그램을 종료합니다.
timeout /t 2 >nul
exit
