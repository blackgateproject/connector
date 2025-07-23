@echo off
REM Performance Testing Batch Script for Windows
REM This script provides easy access to performance testing commands

echo ===============================================================================
echo                    Blackgate Connector - Performance Testing
echo ===============================================================================

if "%1"=="" goto :show_help
if "%1"=="help" goto :show_help
if "%1"=="setup" goto :setup
if "%1"=="validate" goto :validate
if "%1"=="smoke" goto :smoke
if "%1"=="run" goto :run_tests
if "%1"=="individual" goto :individual
if "%1"=="pytest" goto :pytest
if "%1"=="reports" goto :reports
goto :show_help

:setup
echo [SETUP] Installing dependencies and setting up environment...
python -m pip install -r performance_testing\requirements-perf.txt
if errorlevel 1 (
    echo ERROR: Failed to install dependencies
    exit /b 1
)
mkdir performance_reports 2>nul
echo [SETUP] Setup completed successfully!
goto :end

:validate
echo [VALIDATE] Running setup and validation script...
python performance_testing\setup_and_validate.py %2 %3 %4 %5
goto :end

:smoke
echo [SMOKE] Running smoke test with 1 user...
python performance_testing\run_load_tests.py --single-level 1
goto :end

:run_tests
if "%2"=="" (
    echo [RUN] Running all load levels: 100, 200, 400, 800, 1000 users...
    python performance_testing\run_load_tests.py
) else (
    echo [RUN] Running load test for %2 users...
    python performance_testing\run_load_tests.py --single-level %2
)
goto :end

:individual
if "%2"=="" (
    echo ERROR: Please specify number of users (100, 200, 400, 800, or 1000)
    echo Example: perf_test.bat individual 100
    exit /b 1
)
echo [INDIVIDUAL] Running individual test for %2 users...
python performance_testing\individual_tests.py %2
goto :end

:pytest
echo [PYTEST] Running pytest performance tests...
if "%2"=="" (
    pytest performance_testing\ -m performance -v
) else (
    pytest performance_testing\ -m performance -v %2 %3 %4 %5
)
goto :end

:reports
echo [REPORTS] Opening performance reports directory...
if exist performance_reports (
    explorer performance_reports
) else (
    echo No reports directory found. Run tests first.
)
goto :end

:show_help
echo.
echo Usage: perf_test.bat [command] [options]
echo.
echo Commands:
echo   setup           Install dependencies and create directories
echo   validate        Run setup and validation checks
echo   smoke           Run quick smoke test with 1 user
echo   run [users]     Run load tests (all levels or specific count)
echo   individual N    Run individual test for N users (100,200,400,800,1000)
echo   pytest [args]   Run pytest performance tests
echo   reports         Open reports directory
echo   help            Show this help message
echo.
echo Examples:
echo   perf_test.bat setup
echo   perf_test.bat validate --url http://localhost:8000
echo   perf_test.bat smoke
echo   perf_test.bat run
echo   perf_test.bat run 100
echo   perf_test.bat individual 200
echo   perf_test.bat pytest
echo   perf_test.bat reports
echo.
echo Environment Variables (optional):
echo   PERF_TEST_BASE_URL     - API base URL (default: http://localhost:8000)
echo   PERF_TEST_DB_URL       - PostgreSQL connection string
echo   PERF_TEST_OUTPUT_DIR   - Output directory (default: performance_reports)
echo.

:end
echo.
echo ===============================================================================
