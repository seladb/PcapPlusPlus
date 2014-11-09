@ECHO OFF

echo.
echo ******************************************
echo PcapPlusPlus Windows configuration script 
echo ******************************************
echo.

set PLATFORM=mk\platform.mk
if exist %PLATFORM% (del %PLATFORM%)

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
	echo. >>%PLATFORM%
	if "%%A" EQU "MINGW_HOME :=" (echo %%A %MINGW_HOME%>>%PLATFORM%) else (if "%%A" EQU "WINPCAP_HOME :=" (echo %%A %WINPCAP_HOME%>>%PLATFORM%) else (echo %%A>>%PLATFORM%))
)

echo.
echo PcapPlusPlus configuration is complete. File created (or modified): %PLATFORM%
