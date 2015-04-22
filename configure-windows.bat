@ECHO OFF

echo.
echo ******************************************
echo PcapPlusPlus Windows configuration script 
echo ******************************************
echo.

set PLATFORM_MK=mk\platform.mk
set PCAPPLUSPLUS_MK=mk\PcapPlusPlus.mk
if exist %PLATFORM_MK% (del %PLATFORM_MK%)
if exist %PCAPPLUSPLUS_MK% (del %PCAPPLUSPLUS_MK%)

set CUR_DIR=%cd:\=/%
echo PCAPPLUSPLUS_HOME := %CUR_DIR%>> %PLATFORM_MK%
echo. >> %PLATFORM_MK%
echo PCAPPLUSPLUS_HOME := %CUR_DIR%>> %PCAPPLUSPLUS_MK%
echo. >> %PCAPPLUSPLUS_MK%

:: get MinGW location from user and verify it exists
echo MinGW is required for compiling PcapPlusPlus. 
echo If MinGW is not installed, please download and install it from www.mingw.org/
echo.
:while1
set /p MINGW_HOME=    Please specify MinGW installed path: %=%
if not exist %MINGW_HOME%\ (echo Directory does not exist!! && goto while1)
:: replace "\" with "/"
set MINGW_HOME=%MINGW_HOME:\=/%

echo.
echo.


:: get WinPcap dev pack location from user and verify it exists
echo WinPcap developer's pack is required for compiling PcapPlusPlus. 
echo If WinPcap developer's pack is not installed, please download and install it from https://www.winpcap.org/devel.htm
echo.
:while2
set /p WINPCAP_HOME=    Please specify WinPcap developer's pack installed path: %=%
if not exist %WINPCAP_HOME%\ (echo Directory does not exist!! && goto while2)
:: replace "\" with "/"
set WINPCAP_HOME=%WINPCAP_HOME:\=/%

:: set MinGW and WinPcap locations in platform.mk.win32 and create platform.mk
for /F "tokens=1* delims=]" %%A in ('type "mk\platform.mk.win32"') do (
	echo. >>%PLATFORM_MK%
	if "%%A" EQU "MINGW_HOME :=" (echo %%A %MINGW_HOME%>>%PLATFORM_MK%) else (if "%%A" EQU "WINPCAP_HOME :=" (echo %%A %WINPCAP_HOME%>>%PLATFORM_MK%) else (echo %%A>>%PLATFORM_MK%))
)

type mk\PcapPlusPlus.mk.common >> %PCAPPLUSPLUS_MK%
type mk\PcapPlusPlus.mk.win32 >> %PCAPPLUSPLUS_MK%

echo.
echo PcapPlusPlus configuration is complete. Files created (or modified): %PLATFORM_MK%, %PCAPPLUSPLUS_MK%
