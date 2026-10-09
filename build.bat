@echo off
setlocal enabledelayedexpansion
cd /d "%~dp0"

echo ==========================================================
echo   Building Lagg.exe
echo   (trying MSVC cl.exe first, then MinGW g++)
echo ==========================================================

set "ICONFILE=Icon\icon.ico"
set "HAVEICON=0"
if exist "%ICONFILE%" set "HAVEICON=1"

REM ---- MSVC already in PATH? ----
where cl >nul 2>&1
if not errorlevel 1 goto build_msvc

REM ---- Locate Visual Studio via vswhere ----
set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if exist "%VSWHERE%" (
    for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath 2^>nul`) do set "VSPATH=%%i"
    if defined VSPATH (
        if exist "!VSPATH!\VC\Auxiliary\Build\vcvars64.bat" (
            echo Found Visual Studio: !VSPATH!
            call "!VSPATH!\VC\Auxiliary\Build\vcvars64.bat" >nul
            where cl >nul 2>&1
            if not errorlevel 1 goto build_msvc
        )
    )
)
echo MSVC not found, trying MinGW...
goto try_mingw

:build_msvc
echo.
echo [MSVC] using cl.exe
set "RESOBJ="
if "%HAVEICON%"=="1" (
    echo Icon found: %ICONFILE% - compiling resource...
    rc /nologo /fo app.res app.rc
    if not errorlevel 1 (set "RESOBJ=app.res") else (echo [!] rc.exe failed - building without icon.)
) else (
    echo [i] %ICONFILE% not found - building without icon.
)
cl /nologo /std:c++17 /utf-8 /EHsc /O2 /DNDEBUG Lagg.cpp %RESOBJ% /Fe:Lagg.exe /link advapi32.lib shell32.lib /SUBSYSTEM:CONSOLE
if errorlevel 1 goto fail
if exist app.res del app.res
if exist Lagg.obj del Lagg.obj
goto ok

:try_mingw
where g++ >nul 2>&1
if errorlevel 1 (
    echo.
    echo [ERROR] Neither MSVC nor MinGW found.
    echo   MSVC: install "Visual Studio Build Tools" with the
    echo         "Desktop development with C++" workload.
    echo   or install MinGW-w64 ^(MSYS2 / w64devkit^) and add g++ to PATH.
    goto fail
)
echo.
echo [MinGW] using g++
set "RESOBJ="
if "%HAVEICON%"=="1" (
    where windres >nul 2>&1
    if not errorlevel 1 (
        echo Icon found: %ICONFILE% - compiling resource...
        windres app.rc -O coff -o app.res
        if not errorlevel 1 (set "RESOBJ=app.res") else (echo [!] windres failed - building without icon.)
    ) else (
        echo [!] windres not found - building without icon.
    )
) else (
    echo [i] %ICONFILE% not found - building without icon.
)
g++ -std=c++17 -O2 -static -static-libgcc -static-libstdc++ Lagg.cpp %RESOBJ% -o Lagg.exe -lws2_32 -liphlpapi -lwinhttp -lshlwapi -lole32 -ladvapi32 -lshell32
if errorlevel 1 goto fail
if exist app.res del app.res
goto ok

:fail
echo.
echo [ERROR] Build failed. See messages above.
if exist app.res del app.res
pause
exit /b 1

:ok
echo.
echo [OK] Lagg.exe built.
echo.
pause
