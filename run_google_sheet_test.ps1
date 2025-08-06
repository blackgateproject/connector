# PowerShell script for running performance tests
Write-Host "================================================" -ForegroundColor Green
Write-Host "PERFORMANCE TEST FOR GOOGLE SHEET UPDATE" -ForegroundColor Green  
Write-Host "================================================" -ForegroundColor Green
Write-Host ""
Write-Host "Testing with multi-worker async blockchain processing..." -ForegroundColor Yellow
Write-Host "This measures IdIssue, IdProve, IdVerify phases with:" -ForegroundColor Yellow
Write-Host "  - SMT proof sizes in bytes" -ForegroundColor Yellow
Write-Host "  - CPU usage for all processes" -ForegroundColor Yellow  
Write-Host "  - Blockchain update times" -ForegroundColor Yellow
Write-Host ""

# Navigate to script directory
Set-Location $PSScriptRoot

# Activate virtual environment
& .\.venv\Scripts\Activate.ps1

# For multi-worker testing (optional)
$env:MULTI_WORKER_MODE = "true"
$env:BLOCKCHAIN_WORKERS = "3"
$env:BLOCKCHAIN_BATCH_SIZE = "5"

# Run the comprehensive performance test
Write-Host "Running performance test..." -ForegroundColor Cyan
python -m performance_testing.comprehensive_google_sheet_test

Write-Host ""
Write-Host "================================================" -ForegroundColor Green
Write-Host "TEST COMPLETED - Results ready for Google Sheet" -ForegroundColor Green
Write-Host "================================================" -ForegroundColor Green

# For full-scale testing with 100-1000 devices, uncomment below:
# Write-Host ""
# Write-Host "For full-scale testing (100-1000 devices), run:" -ForegroundColor Yellow
# Write-Host "fastapi run --workers 4 app.main:app" -ForegroundColor Cyan
# Write-Host "Then modify comprehensive_google_sheet_test.py device_counts to [100, 200, 400, 600, 1000]" -ForegroundColor Cyan
