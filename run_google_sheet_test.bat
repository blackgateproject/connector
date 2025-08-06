@echo off
echo ================================================
echo PERFORMANCE TEST FOR GOOGLE SHEET UPDATE
echo ================================================
echo.
echo Starting FastAPI server and running comprehensive performance test...
echo This will test IdIssue, IdProve, IdVerify phases with SMT proof sizes and CPU usage
echo.

cd /d "%~dp0"

REM Activate virtual environment
call .venv\Scripts\activate.bat

REM Run the comprehensive performance test
python -m performance_testing.comprehensive_google_sheet_test

echo.
echo ================================================
echo TEST COMPLETED - Results ready for Google Sheet
echo ================================================
pause
