# Extract Contract Addresses from deployments-zk
# This script extracts all contract addresses from the deployments-zk folder

Write-Host "🔍 Extracting contract addresses from deployments-zk..." -ForegroundColor Green

# Get the script directory and navigate to the deployments-zk folder
$scriptDir = Split-Path $PSScriptRoot -Parent
$deploymentsPath = Join-Path $scriptDir "blockchain-contracts\deployments-zk"

if (-not (Test-Path $deploymentsPath)) {
    Write-Host "❌ deployments-zk folder not found at: $deploymentsPath" -ForegroundColor Red
    exit 1
}

# Initialize the result object
$contractAddresses = @{}
$extractedContracts = @()

# Function to extract addresses from a JSON file
function Extract-ContractAddresses {
    param (
        [string]$JsonFilePath,
        [string]$NetworkType
    )
    
    try {
        $jsonContent = Get-Content $JsonFilePath -Raw | ConvertFrom-Json
        $contractName = $jsonContent.contractName
        
        if ($jsonContent.entries -and $jsonContent.entries.Count -gt 0) {
            foreach ($entry in $jsonContent.entries) {
                if ($entry.address) {
                    $contractInfo = @{
                        Name = $contractName
                        Address = $entry.address
                        TxHash = $entry.txHash
                        Network = $NetworkType
                        FilePath = $JsonFilePath
                    }
                    
                    Write-Host "✅ Found $contractName at $($entry.address)" -ForegroundColor Green
                    return $contractInfo
                }
            }
        }
    }
    catch {
        Write-Host "⚠️ Error reading $JsonFilePath : $($_.Exception.Message)" -ForegroundColor Yellow
    }
    
    return $null
}

# Get all network directories
$networkDirs = Get-ChildItem -Path $deploymentsPath -Directory
Write-Host "📂 Found network directories: $($networkDirs.Name -join ', ')" -ForegroundColor Cyan

foreach ($networkDir in $networkDirs) {
    $networkName = $networkDir.Name
    Write-Host "🌐 Processing network: $networkName" -ForegroundColor Yellow
    
    # Initialize network section if it doesn't exist
    if (-not $contractAddresses.ContainsKey($networkName)) {
        $contractAddresses[$networkName] = @{}
    }
    
    # Find all JSON files in the contracts subdirectories
    $contractsPath = Join-Path $networkDir.FullName "contracts"
    if (Test-Path $contractsPath) {
        $jsonFiles = Get-ChildItem -Path $contractsPath -Recurse -Filter "*.json"
        
        foreach ($jsonFile in $jsonFiles) {
            $contractInfo = Extract-ContractAddresses -JsonFilePath $jsonFile.FullName -NetworkType $networkName
            if ($contractInfo) {
                $contractAddresses[$networkName][$contractInfo.Name] = $contractInfo.Address
                $extractedContracts += $contractInfo
            }
        }
    }
}

# Create output files
$outputDir = Join-Path $scriptDir "contract_addresses"
if (-not (Test-Path $outputDir)) {
    New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
}

# Generate detailed JSON report
$detailedReport = @{
    timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    networks = $contractAddresses
    contracts = $extractedContracts
}

$jsonOutputPath = Join-Path $outputDir "contract_addresses.json"
$detailedReport | ConvertTo-Json -Depth 10 | Set-Content -Path $jsonOutputPath -Encoding UTF8

# Generate summary text file
$summaryOutputPath = Join-Path $outputDir "contract_addresses_summary.txt"
$summaryContent = @"
Contract Addresses Summary
Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
========================================

"@

foreach ($network in $contractAddresses.Keys) {
    $summaryContent += "`n[$network Network]`n"
    $summaryContent += "-" * ($network.Length + 10) + "`n"
    
    foreach ($contract in $contractAddresses[$network].Keys) {
        $address = $contractAddresses[$network][$contract]
        $summaryContent += "$contract = $address`n"
    }
}

$summaryContent | Set-Content -Path $summaryOutputPath -Encoding UTF8

# Generate environment variable format
$envOutputPath = Join-Path $outputDir "contract_addresses.env"
$envContent = @"
# Contract Addresses - Generated $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
# ========================================

"@

foreach ($network in $contractAddresses.Keys) {
    $envContent += "`n# $network Network`n"
    
    foreach ($contract in $contractAddresses[$network].Keys) {
        $address = $contractAddresses[$network][$contract]
        $envVarName = "$($network.ToUpper())_$($contract.ToUpper())_ADDRESS"
        $envContent += "$envVarName=$address`n"
    }
}

$envContent | Set-Content -Path $envOutputPath -Encoding UTF8

# Generate Python/JavaScript compatible format
$pyOutputPath = Join-Path $outputDir "contract_addresses.py"
$pyContent = @"
# Contract Addresses - Generated $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
# ========================================

CONTRACT_ADDRESSES = {
"@

foreach ($network in $contractAddresses.Keys) {
    $pyContent += "`n    '$network': {`n"
    
    foreach ($contract in $contractAddresses[$network].Keys) {
        $address = $contractAddresses[$network][$contract]
        $pyContent += "        '$contract': '$address',`n"
    }
    
    $pyContent += "    },`n"
}

$pyContent += "}`n"
$pyContent | Set-Content -Path $pyOutputPath -Encoding UTF8

# Summary report
Write-Host "`n🎉 Contract address extraction completed!" -ForegroundColor Green
Write-Host "📊 Summary:" -ForegroundColor Cyan
Write-Host "  📂 Networks processed: $($contractAddresses.Keys.Count)" -ForegroundColor White
Write-Host "  📄 Contracts found: $($extractedContracts.Count)" -ForegroundColor White
Write-Host "  📁 Output directory: $outputDir" -ForegroundColor White

Write-Host "`n📄 Generated files:" -ForegroundColor Cyan
Write-Host "  • contract_addresses.json      - Detailed JSON report" -ForegroundColor White
Write-Host "  • contract_addresses_summary.txt - Human-readable summary" -ForegroundColor White
Write-Host "  • contract_addresses.env       - Environment variable format" -ForegroundColor White
Write-Host "  • contract_addresses.py        - Python dictionary format" -ForegroundColor White

# Display the contracts found
Write-Host "`n📋 Contracts found:" -ForegroundColor Cyan
foreach ($contract in $extractedContracts) {
    Write-Host "  🔗 $($contract.Name) [$($contract.Network)] → $($contract.Address)" -ForegroundColor White
}
