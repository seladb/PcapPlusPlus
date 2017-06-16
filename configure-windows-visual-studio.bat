@echo OFF
setlocal

echo.
echo ****************************************************
echo PcapPlusPlus Visual Studio 2015 configuration script 
echo ****************************************************
echo.

set VS_PROPERTY_SHEET=mk\vs2015\PcapPlusPlusPropertySheet.props
set VS_PROPERTY_SHEET_TEMPLATE=%VS_PROPERTY_SHEET%.template

:: initially set WINPCAP_HOME and PTHREAD_HOME to empty values
set WINPCAP_HOME=
set PTHREAD_HOME=

:: check the number of arguments: If got at least one argument continue to command-line mode, else continue to wizard mode
if "%1" NEQ "" ( 
	call :GETOPT %1 %2 %3 %4 %5 %6 %7 %8 %9 
) else ( 
	call :READ_PARAMS_FROM_USER 
)
:: if one of the modes returned with an error, exit script
if "%ERRORLEVEL%" NEQ "0" exit /B 1

:: verify that both variables PTHREAD_HOME and WINPCAP_HOME are set
if "%PTHREAD_HOME%"=="" echo pthread-win32 directory was not supplied. Exiting & exit /B 1
if "%WINPCAP_HOME%"=="" echo WinPcap directory was not supplied. Exiting & exit /B 1

:: remove trailing "\" in PTHREAD_HOME if exists
if "%PTHREAD_HOME:~-1%"=="\" set PTHREAD_HOME=%PTHREAD_HOME:~,-1%
:: remove trailing "\" in WINPCAP_HOME if exists
if "%WINPCAP_HOME:~-1%"=="\" set WINPCAP_HOME=%WINPCAP_HOME:~,-1%

:: set PcapPlusPlus home, pthread-win32 and WinPcap locations in %VS_PROPERTY_SHEET%
(for /F "tokens=* delims=" %%A in ('type "%VS_PROPERTY_SHEET_TEMPLATE%"') do (
    set "LINE=%%A"
    setlocal enabledelayedexpansion
    set "LINE=!LINE:PUT_PCAPPLUSPLUS_HOME_HERE=%cd%!"
	set "LINE=!LINE:PUT_WIN_PCAP_HOME_HERE=%WINPCAP_HOME%!"
	set "LINE=!LINE:PUT_PTHREAD_HOME_HERE=%PTHREAD_HOME%!"
    echo !LINE!
    endlocal
))>pcpp_temp.xml

move /Y pcpp_temp.xml %VS_PROPERTY_SHEET% >nul

:: configuration completed
echo.
echo PcapPlusPlus Visual Studio 2015 configuration is complete. Files created (or modified): %VS_PROPERTY_SHEET%

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

:: handling help switches (-h or --help)
:CASE--help
:CASE-h
	:: call the HELP "function" 
	call :HELP
	:: exit with error code 3, meaning ask the caller to exit the script
	exit /B 3

:: handling -p or --pthread-home switches
:CASE-p
:CASE--pthreadS-home
	:: this argument must have a parameter. If no parameter was found goto GETOPT_REQUIRED_PARAM and exit
	if "%2"=="" goto GETOPT_REQUIRED_PARAM %1
	:: verify the MSYS dir supplied by the user exists. If not, exit with error code 3, meaning ask the caller to exit the script
	if not exist %2\ call :GETOPT_ERROR "pthreads-win32 directory '%2' does not exist" & exit /B 3
	:: if all went well, set the PTHREAD_HOME variable with the directory given by the user
	set PTHREAD_HOME=%2
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

:: get WinPcap dev pack location from user and verify it exists
echo WinPcap developer's pack is required for compiling PcapPlusPlus. 
echo If WinPcap developer's pack is not installed, please download and install it from https://www.winpcap.org/devel.htm
echo.
:while1
:: ask the user to type WinPcap dir
set /p WINPCAP_HOME=    Please specify WinPcap developer's pack installed path: %=%
:: if input dir doesn't exist print an error to the user and go back to previous line
if not exist %WINPCAP_HOME%\ (echo Directory does not exist!! && goto while1)

echo.
echo.

:: get pthreads-win32 location from user and verify it exists
echo pthreads-win32 is required for compiling PcapPlusPlus. 
echo If you didn't download it already, please download it from here: ftp://sourceware.org/pub/pthreads-win32/pthreads-w32-2-9-1-release.zip
echo.
:while2
:: ask the user to type pthreads-win32 dir
set /p PTHREAD_HOME=    Please specify pthreads-win32 path: %=%
:: if input dir doesn't exist print an error to the user and go back to previous line
if not exist %PTHREAD_HOME%\ (echo Directory does not exist!! && goto while2)


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
echo Basic usage: %~nx0 [-h] -p PTHREADS_WIN32_DIR -w WINPCAP_HOME_DIR
echo.
echo The following switches are recognized:
echo -p^|--pthreads-home   --Sets pthreads-win32 home directory
echo -w^|--winpcap-home    --Sets WinPcap home directory
echo -h^|--help            --Displays this help message and exits. No further actions are performed
echo.
:: done printing, exit
exit /B 0