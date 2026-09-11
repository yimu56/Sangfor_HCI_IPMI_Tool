@echo off
REM Build both binaries:
REM   BmcIpTool.exe - the GUI tool that changes the BMC management IP
REM   BmcMock.exe   - the mock BMC server used for testing without real hardware
REM
REM Requirements: Go 1.21+   Optional: rsrc for modern visual styles

cd /d "%~dp0"
set GOPROXY=https://goproxy.cn,direct

echo [1/3] Running tests...
go test ./...
if errorlevel 1 (
  echo Tests FAILED. Aborting.
  pause
  exit /b 1
)

echo [2/3] Generating windows resources...
where rsrc >nul 2>nul
if errorlevel 1 (
  echo   rsrc not found - reusing existing rsrc.syso
  echo   To install: go install github.com/akavel/rsrc@latest
) else (
  rsrc -manifest app.manifest -arch amd64 -o rsrc.syso
)

echo [3/3] Building...
go build -trimpath -ldflags="-H windowsgui -s -w" -o BmcIpTool.exe .
if errorlevel 1 (
  echo Build FAILED: BmcIpTool.exe
  pause
  exit /b 1
)
go build -trimpath -ldflags="-s -w" -o BmcMock.exe ./bmcmock
if errorlevel 1 (
  echo Build FAILED: BmcMock.exe
  pause
  exit /b 1
)

echo.
echo Done:
echo   %CD%\BmcIpTool.exe
echo   %CD%\BmcMock.exe
pause
