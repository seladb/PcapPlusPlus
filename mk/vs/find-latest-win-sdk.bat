@ECHO OFF

@REM Detect the newest available Windows SDK
CALL :GetWindowsSdkVer

EXIT /B 0

:GetWindowsSdkVer
SET WindowsTargetPlatformVersion=

IF "%WindowsTargetPlatformVersion%"=="" CALL :GetWin10SdkVer
IF "%WindowsTargetPlatformVersion%"=="" CALL :GetWin81SdkVer
EXIT /B 0

:GetWin10SdkVer
CALL :GetWin10SdkVerHelper HKLM\SOFTWARE\Wow6432Node > nul 2>&1
IF errorlevel 1 CALL :GetWin10SdkVerHelper HKCU\SOFTWARE\Wow6432Node > nul 2>&1
IF errorlevel 1 CALL :GetWin10SdkVerHelper HKLM\SOFTWARE > nul 2>&1
IF errorlevel 1 CALL :GetWin10SdkVerHelper HKCU\SOFTWARE > nul 2>&1
IF errorlevel 1 EXIT /B 1
EXIT /B 0

:GetWin10SdkVerHelper
@REM Get Windows 10 SDK installed folder
FOR /F "tokens=1,2*" %%i IN ('reg query "%1\Microsoft\Microsoft SDKs\Windows\v10.0" /v "InstallationFolder"') DO (
    IF "%%i"=="InstallationFolder" (
        SET WindowsSdkDir=%%~k
    )
)

@REM get windows 10 sdk version number
SETLOCAL enableDelayedExpansion
IF NOT "%WindowsSdkDir%"=="" FOR /f %%i IN ('dir "%WindowsSdkDir%include\" /b /ad-h /on') DO (
    @REM Skip if Windows.h is not found in %%i\um.  This would indicate that only the UCRT MSIs were
    @REM installed for this Windows SDK version.
    IF EXIST "%WindowsSdkDir%include\%%i\um\Windows.h" (
        SET result=%%i
        IF "!result:~0,3!"=="10." (
            SET SDK=!result!
            IF "!result!"=="%VSCMD_ARG_WINSDK%" SET findSDK=1
        )
    )
)

IF "%findSDK%"=="1" SET SDK=%VSCMD_ARG_WINSDK%
ENDLOCAL & SET WindowsTargetPlatformVersion=%SDK%
IF "%WindowsTargetPlatformVersion%"=="" (
  EXIT /B 1
)
EXIT /B 0

:GetWin81SdkVer
SET WindowsTargetPlatformVersion=8.1
EXIT /B 0