@echo OFF
setlocal

echo.
echo ******************************************
echo PcapPlusPlus Windows configuration script 
echo ******************************************
echo.

set PLATFORM_MK=mk\platform.mk
set PCAPPLUSPLUS_MK=mk\PcapPlusPlus.mk

:: initially set MINGW_TYPE, MINGW_HOME and WINPCAP_HOME to empty values
set MINGW_TYPE=
set MINGW_HOME=
set WINPCAP_HOME=

:: check the number of arguments: If got at least one argument continue to command-line mode, else continue to wizard mode
if "%1" NEQ "" ( 
	call :GETOPT %1 %2 %3 %4 %5 %6 %7 %8 %9 
) else ( 
	call :READ_PARAMS_FROM_USER 
)
:: if one of the modes returned with an error, exit script
if "%ERRORLEVEL%" NEQ "0" exit /B 1

:: verify that both variables MINGW_HOME, WINPCAP_HOME, MSYS_HOME are set
if "%MINGW_TYPE%"=="" echo MinGW compiler (mingw32 or mingw-w64) was not supplied. Exiting & exit /B 1
if "%MINGW_HOME%"=="" echo MinGW directory was not supplied. Exiting & exit /B 1
if "%MINGW_TYPE%"=="mingw-w64" if "%MSYS_HOME%"=="" echo MSYS/MSYS2 directory was not supplied. Exiting & exit /B 1
if "%MINGW_TYPE%"=="mingw32" set MSYS_HOME=$(MINGW_HOME)/msys/1.0
if "%WINPCAP_HOME%"=="" echo WinPcap directory was not supplied. Exiting & exit /B 1

:: replace "\" with "/" in MINGW_HOME
set MINGW_HOME=%MINGW_HOME:\=/%
:: remove trailing "/" in MINGW_HOME if exists
if "%MINGW_HOME:~-1%"=="/" set MINGW_HOME=%MINGW_HOME:~,-1%
:: replace "\" with "/" in MSYS_HOME
set MSYS_HOME=%MSYS_HOME:\=/%
:: remove trailing "/" in MSYS_HOME if exists
if "%MSYS_HOME:~-1%"=="/" set MSYS_HOME=%MSYS_HOME:~,-1%
:: replace "\" with "/" in WINPCAP_HOME
set WINPCAP_HOME=%WINPCAP_HOME:\=/%
:: remove trailing "/" in WINPCAP_HOME if exists
if "%WINPCAP_HOME:~-1%"=="/" set WINPCAP_HOME=%WINPCAP_HOME:~,-1%

:: delete existing platform.mk and PcapPlusPlus.mk if exist
if exist %PLATFORM_MK% (del %PLATFORM_MK%)
if exist %PCAPPLUSPLUS_MK% (del %PCAPPLUSPLUS_MK%)

:: set directories varaibles in platform.mk
set CUR_DIR=%cd:\=/%
echo PCAPPLUSPLUS_HOME := %CUR_DIR%>> %PLATFORM_MK%
echo. >> %PLATFORM_MK%
echo MINGW_HOME := %MINGW_HOME%>> %PLATFORM_MK%
echo. >> %PLATFORM_MK%
echo WINPCAP_HOME := %WINPCAP_HOME%>> %PLATFORM_MK%
echo. >> %PLATFORM_MK%
echo MSYS_HOME := %MSYS_HOME%>> %PLATFORM_MK%
echo. >> %PLATFORM_MK%

:: copy the content of platform.mk.%MINGW_TYPE% to platform.mk
type mk\platform.mk.%MINGW_TYPE% >> %PLATFORM_MK%


:: set directories varaibles in PcapPlusPlus.mk
echo PCAPPLUSPLUS_HOME := %CUR_DIR%>> %PCAPPLUSPLUS_MK%
echo. >> %PCAPPLUSPLUS_MK%
echo MINGW_HOME := %MINGW_HOME%>> %PCAPPLUSPLUS_MK%
echo. >> %PCAPPLUSPLUS_MK%
echo WINPCAP_HOME := %WINPCAP_HOME%>> %PCAPPLUSPLUS_MK%
echo. >> %PCAPPLUSPLUS_MK%
echo MSYS_HOME := %MSYS_HOME%>> %PCAPPLUSPLUS_MK%
echo. >> %PCAPPLUSPLUS_MK%

:: copy the content of PcapPlusPlus.mk.common to PcapPlusPlus.mk
type mk\PcapPlusPlus.mk.common >> %PCAPPLUSPLUS_MK%
:: copy the content of PcapPlusPlus.mk.%MINGW_TYPE% to PcapPlusPlus.mk (append current content)
type mk\PcapPlusPlus.mk.%MINGW_TYPE% >> %PCAPPLUSPLUS_MK%

:: configuration completed
echo.
echo PcapPlusPlus configuration is complete. Files created (or modified): %PLATFORM_MK%, %PCAPPLUSPLUS_MK%

:: exit script
exit /B 0


:: -------------------------------------------------------------------
:: an implementation of getopt for Windows and specifically for PcapPlusPlus
:: this "function" takes as paramters all command-line arguments given by the user who runs the script
:: then it parses the command-line arguments and calls switch cases per argument
:: it returns with the following exit codes:
::   - exit code 0 if arguments were parsed ok
::   - exit code 1 if an unknown argument was given or none arguments were given at all
::   - exit code 2 if a required parameter was not supplied for one of the switches (for example: -g instead of -g <NUM>)
::   - exit code 3 if one of the command-line arguments asked to exit the script (for example the -h switch displays help and exits)
:GETOPT
:: if no arguments were passed exit with error code 1
if "%1"=="" call :GETOPT_ERROR "No parameters suppplied" & exit /B 1

:GETOPT_START
:: the HAS_PARAM varaible states whether the switch has a parameter, for example '-a 111' means switch '-a' has the parameter '111'
:: initially this variable is set to 0
set HAS_PARAM=0

:: if no command-line arguments are left, exit getopt
if "%1"=="" goto GETOPT_END

:: get the next switch (the one in %1) and call the relevant case for that switch
2>NUL call :CASE%1 %1 %2 %3 %4 %5 %6 %7 %8 %9
:: ERRORLEVEL 3 means the case asked to exit script. Return this error code to the caller
if ERRORLEVEL 3 exit /B 3
:: ERRORLEVEL 2 means the current switch doesn't have a required parameter. Return this error code to the caller
if ERRORLEVEL 2 exit /B 2
:: ERRORLEVEL 1 means the switch is unknown (no case was found for it). Return this error code to the caller
if ERRORLEVEL 1 call :GETOPT_ERROR "Unkown parameter %1" & exit /B 1

:: shift-left the command-line arguments, meaning put %2 in %1, %3 in %2, %4 in %3 and so on. This way %1 always holds the next switch to parse and handle
shift /1
:: if the current switch had a parameter shift again because %1 now has the parameter and we want to get to the next switch
if "%HAS_PARAM%"=="1" shift /1
:: return to GETOPT_START to handle the next switch
goto GETOPT_START

:CASEmingw32
	set MINGW_TYPE=%1
	:: exit ok
	exit /B 0
	
:CASEmingw-w64
	set MINGW_TYPE=%1
	:: exit ok
	exit /B 0

:: handling help switches (-h or --help)
:CASE--help
:CASE-h
	:: call the HELP "function" 
	call :HELP
	:: exit with error code 3, meaning ask the caller to exit the script
	exit /B 3

:: handling -m or --mingw-home switches
:CASE-m
:CASE--mingw-home
	:: this argument must have a parameter. If no parameter was found goto GETOPT_REQUIRED_PARAM and exit
	if "%2"=="" goto GETOPT_REQUIRED_PARAM %1
	:: verify the MinGW dir supplied by the user exists. If not, exit with error code 3, meaning ask the caller to exit the script
	if not exist %2\ call :GETOPT_ERROR "MinGW directory '%2' does not exist" & exit /B 3
	:: if all went well, set the MINGW_HOME variable with the directory given by the user
	set MINGW_HOME=%2
	:: notify GETOPT this switch has a parameter
	set HAS_PARAM=1
	:: exit ok
	exit /B 0

:: handling -s or --msys-home switches
:CASE-s
:CASE--msys-home
	:: this argument must have a parameter. If no parameter was found goto GETOPT_REQUIRED_PARAM and exit
	if "%2"=="" goto GETOPT_REQUIRED_PARAM %1
	:: verify the MSYS dir supplied by the user exists. If not, exit with error code 3, meaning ask the caller to exit the script
	if not exist %2\ call :GETOPT_ERROR "MSYS/MSYS2 directory '%2' does not exist" & exit /B 3
	:: if all went well, set the MSYS_HOME variable with the directory given by the user
	set MSYS_HOME=%2
	:: notify GETOPT this switch has a parameter
	set HAS_PARAM=1
	:: exit ok
	exit /B 0

:: handling -w or --winpcap-home switches
:CASE-w
:CASE--winpcap-home
	:: this argument must have a parameter. If no parameter was found goto GETOPT_REQUIRED_PARAM and exit
	if "%2"=="" goto GETOPT_REQUIRED_PARAM %1
	:: verify the WinPcap dir supplied by the user exists. If not, exit with error code 3, meaning ask the caller to exit the script
	if not exist %2\ call :GETOPT_ERROR "WinPcap directory '%2' does not exist" & exit /B 3
	:: if all went well, set the WINPCAP_HOME variable with the directory given by the user
	set WINPCAP_HOME=%2
	:: notify GETOPT this switch has a parameter
	set HAS_PARAM=1
	:: exit ok
	exit /B 0

:: a required parameter error case, may get to here if a parameter was missing for a certain switch
:: the parameter for this "function" is the switch that didn't have the parameter
:GETOPT_REQUIRED_PARAM
	:: print the error message
	echo Required parameter not supplied for switch "%1"
	:: exit with error code 2, meaining switch is missing a parameter
	exit /B 2

:: both switch cases and getopt may get to here if there was an error that needs to be reported to the user
:: calling this "function" has one parameter which is the error to print to the user
:GETOPT_ERROR
	:: reset error level
	VER > NUL # reset ERRORLEVEL
	:: print the error as was supplied by the user. The %~1 removes quotes if were given
	echo %~1
	:: exit with error code 1
	exit /B 1

:: getopt finished successfully, exit ok
:GETOPT_END
	exit /B 0


:: -------------------------------------------------------------------
:: a "function" that implements the wizard mode which reads MinGW home and WinPcap home by displaying a wizard for the user
:READ_PARAMS_FROM_USER

echo MinGW32 or MinGW-w64 are required for compiling PcapPlusPlus. Please specify 
echo the type you want to use (can be either "mingw32" or "mingw-w64")
echo.
:while0
:: ask the user to type MinGW type
set /p MINGW_TYPE=    Please specify mingw32 or mingw-w64: %=%
if "%MINGW_TYPE%" NEQ "mingw32" if "%MINGW_TYPE%" NEQ "mingw-w64" (echo Please choose one of "mingw32" or "mingw-w64" && goto while0)

echo.
echo.

:: get MinGW location from user and verify it exists
echo If %MINGW_TYPE% is not installed, please download and install it
if "%MINGW_TYPE%"=="mingw32" echo mingw32 can be downloaded from: www.mingw.org/
if "%MINGW_TYPE%"=="mingw-w64" echo mingw-w64 can be downloaded from: sourceforge.net/projects/mingw-w64/
echo.
:while1
:: ask the user to type MinGW dir
set /p MINGW_HOME=    Please specify %MINGW_TYPE% installed path (the folder that includes "bin", "lib" and "include" directories): %=%
:: if input dir doesn't exist print an error to the user and go back to previous line
if not exist %MINGW_HOME%\ (echo Directory does not exist!! && goto while1)

echo.
echo.

if "%MINGW_TYPE%"=="mingw32" goto msys-not-required

:: get MSYS location from user and verify it exists
echo MSYS or MSYS2 are required for compiling PcapPlusPlus. 
echo If MSYS/MSYS2 are not installed, please download and install it
echo.
:while3
:: ask the user to type MSYS dir
set /p MSYS_HOME=    Please specify MSYS/MSYS2 installed path: %=%
:: if input dir doesn't exist print an error to the user and go back to previous line
if not exist %MSYS_HOME%\ (echo Directory does not exist!! && goto while3)

echo.
echo.

:msys-not-required

:: get WinPcap dev pack location from user and verify it exists
echo WinPcap developer's pack is required for compiling PcapPlusPlus. 
echo If WinPcap developer's pack is not installed, please download and install it from https://www.winpcap.org/devel.htm
echo.
:while2
:: ask the user to type WinPcap dir
set /p WINPCAP_HOME=    Please specify WinPcap developer's pack installed path: %=%
:: if input dir doesn't exist print an error to the user and go back to previous line
if not exist %WINPCAP_HOME%\ (echo Directory does not exist!! && goto while2)
:: both directories were read correctly, return to the caller

exit /B 0


:: -------------------------------------------------------------------
:: a "function" that prints help for this script
:HELP
echo.
echo Help documentation for %~nx0
echo This script has 2 modes of operation:
echo   1) Without any switches. In this case the script will guide you through using wizards
echo   2) With switches, as described below
echo.
echo Basic usage: %~nx0 [-h] MINGW_COMPILER -m MINGW_HOME_DIR -w WINPCAP_HOME_DIR [-s MSYS_HOME_DIR]
echo.
echo The following switches are recognized:
echo MINGW_COMPILER        --The MinGW compiler to use. Can be either "mingw32" or "mingw-w64"
echo -m^|--mingw-home      --Sets MinGW home directory (the folder that includes "bin", "lib" and "include" directories)
echo -s^|--msys-home       --Sets MSYS or MSYS2 home directory (must for mingw-w64, not must for mingw32)
echo -w^|--winpcap-home    --Sets WinPcap home directory
echo -h^|--help            --Displays this help message and exits. No further actions are performed
echo.
:: done printing, exit
exit /B 0