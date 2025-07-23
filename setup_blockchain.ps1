# Blockchain Local Setup Script
# This script sets up the local blockchain environment and deploys contracts

Write-Host "🚀 Starting Blockchain Local Setup..." -ForegroundColor Green

# Step 1: Delete existing blockchain containers
Write-Host "📦 Removing existing blockchain containers..." -ForegroundColor Yellow

# First stop any running containers
Write-Host "🛑 Stopping containers..." -ForegroundColor Cyan
docker stop zksync-1 postgres-1 reth-1 2>$null
docker stop blockchain-local-setup-zksync-1 blockchain-local-setup-postgres-1 blockchain-local-setup-reth-1 2>$null

# Remove containers with multiple possible naming patterns
Write-Host "🗑️ Removing containers..." -ForegroundColor Cyan
docker rm -f zksync-1 postgres-1 reth-1 2>$null
docker rm -f blockchain-local-setup-zksync-1 blockchain-local-setup-postgres-1 blockchain-local-setup-reth-1 2>$null

# Remove all containers that might be related to blockchain setup
$containers = docker ps -aq --filter "name=zksync" --filter "name=postgres" --filter "name=reth" 2>$null
if ($containers) {
    foreach ($container in $containers) {
        Write-Host "🗑️ Removing container: $container" -ForegroundColor Cyan
        docker rm -f $container 2>$null
    }
}

Write-Host "✅ Container cleanup completed" -ForegroundColor Green

# Step 2: Navigate to blockchain-local-setup and start containers
Write-Host "🔧 Starting blockchain local setup..." -ForegroundColor Yellow
$originalPath = Get-Location
$blockchainSetupPath = Join-Path (Split-Path $PSScriptRoot -Parent) "blockchain-local-setup"

if (Test-Path $blockchainSetupPath) {
    Set-Location $blockchainSetupPath
    Write-Host "📂 Changed to directory: $blockchainSetupPath" -ForegroundColor Cyan
    
    Write-Host "🐳 Running docker compose up -d..." -ForegroundColor Yellow
    docker compose up -d
    
    if ($LASTEXITCODE -ne 0) {
        Write-Host "❌ Failed to start blockchain containers" -ForegroundColor Red
        Set-Location $originalPath
        exit 1
    }
    Write-Host "✅ Blockchain containers started" -ForegroundColor Green
} else {
    Write-Host "❌ blockchain-local-setup directory not found at: $blockchainSetupPath" -ForegroundColor Red
    exit 1
}

# Step 3: Wait for zksync-1 container to be healthy
Write-Host "⏳ Waiting for zksync-1 container to be healthy..." -ForegroundColor Yellow
$maxAttempts = 120  # Wait up to 10 minutes (60 * 10 seconds)
$attempt = 0

do {
    $attempt++
    Write-Host "🔍 Health check attempt $attempt/$maxAttempts..." -ForegroundColor Cyan
    
    try {
        $response = Invoke-WebRequest -Uri "http://127.0.0.1:3050/health" -TimeoutSec 5 -ErrorAction Stop
        if ($response.StatusCode -eq 200 -or $response.StatusCode -eq 405) {
            Write-Host "✅ zksync-1 container is healthy!" -ForegroundColor Green
            break
        }
    } catch {
        # Check if the exception contains a 405 status code
        if ($_.Exception.Response.StatusCode -eq 405) {
            Write-Host "✅ zksync-1 container is healthy! (405 Method Not Allowed is acceptable)" -ForegroundColor Green
            break
        }
        Write-Host "⏳ zksync-1 not ready yet... waiting 5 seconds" -ForegroundColor Yellow
    }
    
    Start-Sleep -Seconds 5
    
    if ($attempt -ge $maxAttempts) {
        Write-Host "❌ Timeout: zksync-1 container did not become healthy within 10 minutes" -ForegroundColor Red
        Set-Location $originalPath
        exit 1
    }
} while ($true)

# Step 4: Navigate to blockchain-contracts and deploy
Write-Host "📝 Deploying blockchain contracts..." -ForegroundColor Yellow
$contractsPath = Join-Path (Split-Path $PSScriptRoot -Parent) "blockchain-contracts"

if (Test-Path $contractsPath) {
    Set-Location $contractsPath
    Write-Host "📂 Changed to directory: $contractsPath" -ForegroundColor Cyan
    
    # Clean previous builds
    Write-Host "🧹 Cleaning previous builds..." -ForegroundColor Yellow
    npm run clean
    if ($LASTEXITCODE -ne 0) {
        Write-Host "❌ Failed to clean previous builds" -ForegroundColor Red
        Set-Location $originalPath
        exit 1
    }
    
    # Compile contracts
    Write-Host "🔨 Compiling contracts..." -ForegroundColor Yellow
    npm run compile
    if ($LASTEXITCODE -ne 0) {
        Write-Host "❌ Failed to compile contracts" -ForegroundColor Red
        Set-Location $originalPath
        exit 1
    }
    
    # Deploy contracts locally
    Write-Host "🚀 Deploying contracts to local network..." -ForegroundColor Yellow
    npm run deploy-local
    if ($LASTEXITCODE -ne 0) {
        Write-Host "❌ Failed to deploy contracts" -ForegroundColor Red
        Set-Location $originalPath
        exit 1
    }
    
    Write-Host "✅ Contracts deployed successfully!" -ForegroundColor Green
    
    # Step 5: Copy deployments-zk folder to connector/app/utils/
    Write-Host "📁 Copying deployments-zk folder to connector..." -ForegroundColor Yellow
    $deploymentsSource = Join-Path $contractsPath "deployments-zk"
    $deploymentsDestination = Join-Path $originalPath "app\utils\deployments-zk"
    
    if (Test-Path $deploymentsSource) {
        # Remove existing deployments-zk folder if it exists
        if (Test-Path $deploymentsDestination) {
            Write-Host "🗑️ Removing existing deployments-zk folder..." -ForegroundColor Cyan
            Remove-Item -Path $deploymentsDestination -Recurse -Force
        }
        
        # Copy the new deployments-zk folder
        Write-Host "📋 Copying deployments-zk from $deploymentsSource to $deploymentsDestination..." -ForegroundColor Cyan
        Copy-Item -Path $deploymentsSource -Destination $deploymentsDestination -Recurse -Force
        Write-Host "✅ Deployments copied successfully!" -ForegroundColor Green
        
        # Step 6: Extract contract addresses
        Write-Host "📋 Extracting contract addresses..." -ForegroundColor Yellow
        $extractScript = Join-Path $originalPath "extract_contract_addresses.ps1"
        if (Test-Path $extractScript) {
            & $extractScript
            Write-Host "✅ Contract addresses extracted!" -ForegroundColor Green
            
            # Step 7: Update .env files with new contract addresses
            Write-Host "🔧 Updating .env files with contract addresses..." -ForegroundColor Yellow
            $parentDirectory = Split-Path $originalPath -Parent
            $contractAddressesFile = Join-Path $parentDirectory "contract_addresses\contract_addresses.json"
            Write-Host "🔍 Looking for contract addresses JSON at: $contractAddressesFile" -ForegroundColor Cyan
            
            if (Test-Path $contractAddressesFile) {
                $contractData = Get-Content $contractAddressesFile | ConvertFrom-Json
                $dockerizedNodeContracts = $contractData.networks.dockerizedNode
                
                if ($dockerizedNodeContracts) {
                    # Update credential-issuer .env file
                    $credentialIssuerEnvPath = Join-Path $parentDirectory "credential-issuer\.env"
                    Write-Host "🔍 Looking for credential-issuer .env at: $credentialIssuerEnvPath" -ForegroundColor Cyan
                    
                    if (Test-Path $credentialIssuerEnvPath) {
                        Write-Host "📝 Updating credential-issuer .env file..." -ForegroundColor Cyan
                        
                        if ($dockerizedNodeContracts.EthereumDIDRegistry) {
                            $envContent = Get-Content $credentialIssuerEnvPath -Raw
                            $newContent = $envContent -replace 'BLOCKCHAIN_DID_REGISTRY_ADDR=.*', "BLOCKCHAIN_DID_REGISTRY_ADDR=$($dockerizedNodeContracts.EthereumDIDRegistry)"
                            $newContent | Set-Content $credentialIssuerEnvPath -NoNewline
                            Write-Host "  ✅ Updated BLOCKCHAIN_DID_REGISTRY_ADDR: $($dockerizedNodeContracts.EthereumDIDRegistry)" -ForegroundColor Green
                        }
                        
                        if ($dockerizedNodeContracts.Merkle) {
                            $envContent = Get-Content $credentialIssuerEnvPath -Raw
                            $newContent = $envContent -replace 'BLOCKCHAIN_MERKLE_ADDR=.*', "BLOCKCHAIN_MERKLE_ADDR=$($dockerizedNodeContracts.Merkle)"
                            $newContent | Set-Content $credentialIssuerEnvPath -NoNewline
                            Write-Host "  ✅ Updated BLOCKCHAIN_MERKLE_ADDR: $($dockerizedNodeContracts.Merkle)" -ForegroundColor Green
                        }
                    } else {
                        Write-Host "  ⚠️ credential-issuer .env file not found at: $credentialIssuerEnvPath" -ForegroundColor Yellow
                    }
                    
                    # Update frontend .env file
                    $frontendEnvPath = Join-Path $parentDirectory "frontend\.env"
                    Write-Host "🔍 Looking for frontend .env at: $frontendEnvPath" -ForegroundColor Cyan
                    
                    if (Test-Path $frontendEnvPath) {
                        Write-Host "📝 Updating frontend .env file..." -ForegroundColor Cyan
                        
                        if ($dockerizedNodeContracts.EthereumDIDRegistry) {
                            $envContent = Get-Content $frontendEnvPath -Raw
                            $newContent = $envContent -replace 'VITE_BLOCKCHAIN_DID_REGISTRY_ADDR=.*', "VITE_BLOCKCHAIN_DID_REGISTRY_ADDR=$($dockerizedNodeContracts.EthereumDIDRegistry)"
                            $newContent | Set-Content $frontendEnvPath -NoNewline
                            Write-Host "  ✅ Updated VITE_BLOCKCHAIN_DID_REGISTRY_ADDR: $($dockerizedNodeContracts.EthereumDIDRegistry)" -ForegroundColor Green
                        }
                    } else {
                        Write-Host "  ⚠️ frontend .env file not found at: $frontendEnvPath" -ForegroundColor Yellow
                    }
                    
                    Write-Host "✅ Environment files updated successfully!" -ForegroundColor Green
                } else {
                    Write-Host "⚠️ No dockerizedNode contracts found in extracted data" -ForegroundColor Yellow
                }
            } else {
                Write-Host "⚠️ Contract addresses JSON file not found" -ForegroundColor Yellow
            }
        } else {
            Write-Host "⚠️ Contract address extraction script not found" -ForegroundColor Yellow
        }
    } else {
        Write-Host "⚠️ deployments-zk folder not found at: $deploymentsSource" -ForegroundColor Yellow
    }
} else {
    Write-Host "❌ blockchain-contracts directory not found at: $contractsPath" -ForegroundColor Red
    Set-Location $originalPath
    exit 1
}

# Return to original directory
Set-Location $originalPath

Write-Host "🎉 Blockchain setup completed successfully!" -ForegroundColor Green
Write-Host "📋 Summary:" -ForegroundColor Cyan
Write-Host "  ✅ Removed old containers (zksync-1, postgres-1, reth-1)" -ForegroundColor White
Write-Host "  ✅ Started blockchain local setup" -ForegroundColor White
Write-Host "  ✅ Waited for zksync-1 health check" -ForegroundColor White
Write-Host "  ✅ Cleaned, compiled, and deployed contracts" -ForegroundColor White
Write-Host "  ✅ Copied deployments-zk folder to connector/app/utils/" -ForegroundColor White
Write-Host "  ✅ Extracted contract addresses to contract_addresses/" -ForegroundColor White
Write-Host "  ✅ Updated .env files in credential-issuer and frontend" -ForegroundColor White
Write-Host ""
Write-Host "🔗 Your local blockchain is ready at: http://127.0.0.1:3050" -ForegroundColor Green
