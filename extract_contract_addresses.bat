@echo off
echo Extracting contract addresses from deployments-zk...

set "SCRIPT_DIR=%~dp0"
set "DEPLOYMENTS_PATH=%SCRIPT_DIR%..\blockchain-contracts\deployments-zk"
set "OUTPUT_DIR=%SCRIPT_DIR%contract_addresses"

if not exist "%DEPLOYMENTS_PATH%" (
    echo Error: deployments-zk folder not found at: %DEPLOYMENTS_PATH%
    exit /b 1
)

REM Create output directory
if not exist "%OUTPUT_DIR%" mkdir "%OUTPUT_DIR%"

REM Initialize output files
set "SUMMARY_FILE=%OUTPUT_DIR%\contract_addresses_summary.txt"
set "ENV_FILE=%OUTPUT_DIR%\contract_addresses.env"

echo Contract Addresses Summary > "%SUMMARY_FILE%"
echo Generated: %date% %time% >> "%SUMMARY_FILE%"
echo ======================================== >> "%SUMMARY_FILE%"

echo # Contract Addresses - Generated %date% %time% > "%ENV_FILE%"
echo # ======================================== >> "%ENV_FILE%"

REM Process each network directory
for /d %%N in ("%DEPLOYMENTS_PATH%\*") do (
    set "NETWORK_NAME=%%~nN"
    echo Processing network: %%~nN
    
    echo. >> "%SUMMARY_FILE%"
    echo [%%~nN Network] >> "%SUMMARY_FILE%"
    call :print_separator "%%~nN" >> "%SUMMARY_FILE%"
    
    echo. >> "%ENV_FILE%"
    echo # %%~nN Network >> "%ENV_FILE%"
    
    REM Look for JSON files in contracts subdirectory
    set "CONTRACTS_PATH=%%N\contracts"
    if exist "!CONTRACTS_PATH!" (
        for /r "!CONTRACTS_PATH!" %%F in (*.json) do (
            call :extract_address "%%F" "%%~nN"
        )
    )
)

echo.
echo Contract address extraction completed!
echo Output files created in: %OUTPUT_DIR%
echo   - contract_addresses_summary.txt
echo   - contract_addresses.env
pause
goto :eof

:extract_address
set "JSON_FILE=%~1"
set "NETWORK=%~2"

REM Use PowerShell to parse JSON and extract address
for /f "delims=" %%A in ('powershell -Command "try { $json = Get-Content '%JSON_FILE%' | ConvertFrom-Json; if ($json.entries -and $json.entries[0].address) { Write-Output \"$($json.contractName):$($json.entries[0].address)\" } } catch { }"') do (
    if not "%%A"=="" (
        for /f "tokens=1,2 delims=:" %%B in ("%%A") do (
            echo Found %%B at %%C
            echo %%B = %%C >> "%SUMMARY_FILE%"
            
            REM Create environment variable format
            set "UPPER_NETWORK=%NETWORK%"
            set "UPPER_CONTRACT=%%B"
            call :to_upper UPPER_NETWORK
            call :to_upper UPPER_CONTRACT
            echo !UPPER_NETWORK!_!UPPER_CONTRACT!_ADDRESS=%%C >> "%ENV_FILE%"
        )
    )
)
goto :eof

:print_separator
set "TEXT=%~1"
set "LENGTH=0"
:count_loop
if not "!TEXT:~%LENGTH%,1!"=="" (
    set /a LENGTH+=1
    goto count_loop
)
set /a SEPARATOR_LENGTH=LENGTH+10
set "SEPARATOR="
for /l %%i in (1,1,%SEPARATOR_LENGTH%) do set "SEPARATOR=!SEPARATOR!-"
echo %SEPARATOR%
goto :eof

:to_upper
for %%i in (a b c d e f g h i j k l m n o p q r s t u v w x y z) do (
    call set "%1=%%%1:%%i=%%i%%"
)
goto :eof
