@echo off
rem Builds 1440p_patch.exe: 32-bit, static CRT, no runtime dependencies.
rem The embedded asInvoker manifest is required: without it Windows' installer
rem detection elevates any 32-bit exe whose name contains "patch".
setlocal
cd /d "%~dp0"
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
for /f "usebackq delims=" %%i in (`call "%VSWHERE%" -latest -prerelease -products * -property installationPath`) do set "VSROOT=%%i"
if not defined VSROOT (
  echo Visual Studio with the C++ workload was not found.
  exit /b 1
)
set "PATH=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer;%PATH%"
call "%VSROOT%\VC\Auxiliary\Build\vcvars32.bat" >nul || exit /b 1
cl /nologo /std:c++17 /O2 /W4 /WX /EHsc /MT /DUNICODE /D_UNICODE 1440p_patch.cpp /Fe:1440p_patch.exe /link bcrypt.lib /MANIFEST:EMBED "/MANIFESTUAC:level='asInvoker' uiAccess='false'" || exit /b 1
del /q 1440p_patch.obj 2>nul
echo Built %~dp01440p_patch.exe
