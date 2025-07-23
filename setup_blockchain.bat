@echo off
echo Starting Blockchain Local Setup...

REM Step 1: Delete existing blockchain containers
echo Removing existing blockchain containers...

REM First stop any running containers
echo Stopping containers...
docker stop zksync-1 postgres-1 reth-1 2>nul
docker stop blockchain-local-setup-zksync-1 blockchain-local-setup-postgres-1 blockchain-local-setup-reth-1 2>nul

REM Remove containers with multiple possible naming patterns
echo Removing containers...
docker rm -f zksync-1 postgres-1 reth-1 2>nul
docker rm -f blockchain-local-setup-zksync-1 blockchain-local-setup-postgres-1 blockchain-local-setup-reth-1 2>nul

REM Remove all containers that might be related to blockchain setup
for /f "tokens=*" %%i in ('docker ps -aq --filter "name=zksync" --filter "name=postgres" --filter "name=reth"') do (
    echo Removing container: %%i
    docker rm -f %%i 2>nul
)

echo Container cleanup completed

REM Step 2: Navigate to blockchain-local-setup and start containers
echo Starting blockchain local setup...
set "ORIGINAL_DIR=%CD%"
set "BLOCKCHAIN_SETUP_DIR=%~dp0..\blockchain-local-setup"

if exist "%BLOCKCHAIN_SETUP_DIR%" (
    cd /d "%BLOCKCHAIN_SETUP_DIR%"
    echo Changed to directory: %BLOCKCHAIN_SETUP_DIR%
    
    echo Running docker compose up -d...
    docker compose up -d --build
    
    if %errorlevel% neq 0 (
        echo Failed to start blockchain containers
        cd /d "%ORIGINAL_DIR%"
        exit /b 1
    )
    echo Blockchain containers started
) else (
    echo blockchain-local-setup directory not found at: %BLOCKCHAIN_SETUP_DIR%
    exit /b 1
)

REM Step 3: Wait for zksync-1 container to be healthy
echo Waiting for zksync-1 container to be healthy...
set /a attempts=0
set /a maxAttempts=120

:healthcheck
set /a attempts+=1
echo Health check attempt %attempts%/%maxAttempts%...

curl --fail --silent --connect-timeout 5 http://127.0.0.1:3050/health >nul 2>&1
if %errorlevel% equ 0 (
    echo zksync-1 container is healthy!
    goto contracts
)

REM Check if curl returned a 405 error (which is acceptable)
curl --silent --connect-timeout 5 http://127.0.0.1:3050/health >nul 2>&1
if %errorlevel% equ 22 (
    REM Error 22 typically means HTTP error, check if it's a 405
    curl --silent --write-out "%%{http_code}" --connect-timeout 5 http://127.0.0.1:3050/health | findstr "405" >nul
    if %errorlevel% equ 0 (
        echo zksync-1 container is healthy! (405 Method Not Allowed is acceptable)
        goto contracts
    )
)

echo zksync-1 not ready yet... waiting 5 seconds
timeout /t 5 /nobreak >nul

if %attempts% geq %maxAttempts% (
    echo Timeout: zksync-1 container did not become healthy within 5 minutes
    cd /d "%ORIGINAL_DIR%"
    exit /b 1
)

goto healthcheck

:contracts
REM Step 4: Navigate to blockchain-contracts and deploy
echo Deploying blockchain contracts...
set "CONTRACTS_DIR=%~dp0..\blockchain-contracts"

if exist "%CONTRACTS_DIR%" (
    cd /d "%CONTRACTS_DIR%"
    echo Changed to directory: %CONTRACTS_DIR%
    
    REM Clean previous builds
    echo Cleaning previous builds...
    call npm run clean
    if %errorlevel% neq 0 (
        echo Failed to clean previous builds
        cd /d "%ORIGINAL_DIR%"
        exit /b 1
    )
    
    REM Compile contracts
    echo Compiling contracts...
    call npm run compile
    if %errorlevel% neq 0 (
        echo Failed to compile contracts
        cd /d "%ORIGINAL_DIR%"
        exit /b 1
    )
    
    REM Deploy contracts locally
    echo Deploying contracts to local network...
    call npm run deploy-local
    if %errorlevel% neq 0 (
        echo Failed to deploy contracts
        cd /d "%ORIGINAL_DIR%"
        exit /b 1
    )
    
    echo Contracts deployed successfully!
    
    REM Step 5: Copy deployments-zk folder to connector/app/utils/
    echo Copying deployments-zk folder to connector...
    set "DEPLOYMENTS_SOURCE=%CONTRACTS_DIR%\deployments-zk"
    set "DEPLOYMENTS_DESTINATION=%ORIGINAL_DIR%\app\utils\deployments-zk"
    
    if exist "%DEPLOYMENTS_SOURCE%" (
        REM Remove existing deployments-zk folder if it exists
        if exist "%DEPLOYMENTS_DESTINATION%" (
            echo Removing existing deployments-zk folder...
            rmdir /s /q "%DEPLOYMENTS_DESTINATION%"
        )
        
        REM Copy the new deployments-zk folder
        echo Copying deployments-zk from %DEPLOYMENTS_SOURCE% to %DEPLOYMENTS_DESTINATION%...
        xcopy "%DEPLOYMENTS_SOURCE%" "%DEPLOYMENTS_DESTINATION%" /e /i /y >nul
        if %errorlevel% equ 0 (
            echo Deployments copied successfully!
        
        REM Step 6: Extract contract addresses
        echo Extracting contract addresses...
        if exist "%ORIGINAL_DIR%\extract_contract_addresses.bat" (
            call "%ORIGINAL_DIR%\extract_contract_addresses.bat"
            echo Contract addresses extracted!
            
            REM Step 7: Update .env files with new contract addresses
            echo Updating .env files with contract addresses...
            call :update_env_files
            echo Environment files updated successfully!
        ) else (
            echo Warning: Contract address extraction script not found
        )
        ) else (
            echo Failed to copy deployments-zk folder
        )
    ) else (
        echo Warning: deployments-zk folder not found at: %DEPLOYMENTS_SOURCE%
    )
) else (
    echo blockchain-contracts directory not found at: %CONTRACTS_DIR%
    cd /d "%ORIGINAL_DIR%"
    exit /b 1
)

REM Return to original directory
cd /d "%ORIGINAL_DIR%"

echo.
echo Blockchain setup completed successfully!
echo Summary:
echo   - Removed old containers (zksync-1, postgres-1, reth-1)
echo   - Started blockchain local setup
echo   - Waited for zksync-1 health check
echo   - Cleaned, compiled, and deployed contracts
echo   - Copied deployments-zk folder to connector/app/utils/
echo   - Extracted contract addresses to contract_addresses/
echo   - Updated .env files in credential-issuer and frontend
echo   - Extracted contract addresses to contract_addresses/
echo.
echo Your local blockchain is ready at: http://localhost:3071
pause

:update_env_files
REM Function to update .env files with contract addresses
set "CONTRACT_JSON=%ORIGINAL_DIR%\contract_addresses\contract_addresses.json"

if not exist "%CONTRACT_JSON%" (
    echo Warning: Contract addresses JSON file not found
    goto :eof
)

REM Extract addresses using PowerShell
for /f "delims=" %%A in ('powershell -Command "try { $json = Get-Content '%CONTRACT_JSON%' | ConvertFrom-Json; $contracts = $json.networks.dockerizedNode; if ($contracts.EthereumDIDRegistry) { Write-Output \"DID:$($contracts.EthereumDIDRegistry)\" }; if ($contracts.Merkle) { Write-Output \"MERKLE:$($contracts.Merkle)\" } } catch { }"') do (
    for /f "tokens=1,2 delims=:" %%B in ("%%A") do (
        if "%%B"=="DID" (
            set "DID_REGISTRY_ADDR=%%C"
        )
        if "%%B"=="MERKLE" (
            set "MERKLE_ADDR=%%C"
        )
    )
)

REM Update credential-issuer .env file
set "CREDENTIAL_ISSUER_ENV=%~dp0..\credential-issuer\.env"
if exist "%CREDENTIAL_ISSUER_ENV%" (
    echo Updating credential-issuer .env file...
    
    if defined DID_REGISTRY_ADDR (
        powershell -Command "(Get-Content '%CREDENTIAL_ISSUER_ENV%') -replace '^BLOCKCHAIN_DID_REGISTRY_ADDR=.*', 'BLOCKCHAIN_DID_REGISTRY_ADDR=%DID_REGISTRY_ADDR%' | Set-Content '%CREDENTIAL_ISSUER_ENV%'"
        echo   Updated BLOCKCHAIN_DID_REGISTRY_ADDR: %DID_REGISTRY_ADDR%
    )
    
    if defined MERKLE_ADDR (
        powershell -Command "(Get-Content '%CREDENTIAL_ISSUER_ENV%') -replace '^BLOCKCHAIN_MERKLE_ADDR=.*', 'BLOCKCHAIN_MERKLE_ADDR=%MERKLE_ADDR%' | Set-Content '%CREDENTIAL_ISSUER_ENV%'"
        echo   Updated BLOCKCHAIN_MERKLE_ADDR: %MERKLE_ADDR%
    )
) else (
    echo Warning: credential-issuer .env file not found at: %CREDENTIAL_ISSUER_ENV%
)

REM Update frontend .env file
set "FRONTEND_ENV=%~dp0..\frontend\.env"
if exist "%FRONTEND_ENV%" (
    echo Updating frontend .env file...
    
    if defined DID_REGISTRY_ADDR (
        powershell -Command "(Get-Content '%FRONTEND_ENV%') -replace '^VITE_BLOCKCHAIN_DID_REGISTRY_ADDR=.*', 'VITE_BLOCKCHAIN_DID_REGISTRY_ADDR=%DID_REGISTRY_ADDR%' | Set-Content '%FRONTEND_ENV%'"
        echo   Updated VITE_BLOCKCHAIN_DID_REGISTRY_ADDR: %DID_REGISTRY_ADDR%
    )
) else (
    echo Warning: frontend .env file not found at: %FRONTEND_ENV%
)

goto :eof
