@echo OFF
setlocal

echo.
echo ***********************************************
echo PcapPlusPlus Visual Studio configuration script 
echo ***********************************************
echo.

:: initially set PCAP_SDK_HOME and PTHREAD_HOME to empty values
set PCAP_SDK_HOME=
set PTHREAD_HOME=

:: check the number of arguments: If got at least one argument continue to command-line mode, else continue to wizard mode
if "%1" NEQ "" ( 
	call :GETOPT %1 %2 %3 %4 %5 %6 %7 %8 %9 
) else ( 
	call :READ_PARAMS_FROM_USER 
)
:: if one of the modes returned with an error, exit script
if "%ERRORLEVEL%" NEQ "0" exit /B 1

:: verify that all variables: PTHREAD_HOME, PCAP_SDK_HOME, VS_VERSION are set
if "%VS_VERSION%"=="" echo Visual studio version was not provided. Exiting & exit /B 1
if "%PTHREAD_HOME%"=="" echo pthread-win32 directory was not provided. Exiting & exit /B 1
if "%PCAP_SDK_HOME%"=="" echo WinPcap/Npcap SDK directory was not provided. Exiting & exit /B 1

:: remove trailing "\" in PTHREAD_HOME if exists
if "%PTHREAD_HOME:~-1%"=="\" set PTHREAD_HOME=%PTHREAD_HOME:~,-1%
:: remove trailing "\" in PCAP_SDK_HOME if exists
if "%PCAP_SDK_HOME:~-1%"=="\" set PCAP_SDK_HOME=%PCAP_SDK_HOME:~,-1%

set VS_PROJ_DIR=mk\%VS_VERSION%
set VS_PROPERTY_SHEET=PcapPlusPlusPropertySheet.props
set VS_PROPERTY_SHEET_TEMPLATE=mk\vs\%VS_PROPERTY_SHEET%.template

:: create VS project directory if doesn't exist already
if not exist "%VS_PROJ_DIR%" mkdir %VS_PROJ_DIR%

:: set PcapPlusPlus home, pthread-win32 and WinPcap/Npcap locations in %VS_PROPERTY_SHEET%
(for /F "tokens=* delims=" %%A in ('type "%VS_PROPERTY_SHEET_TEMPLATE%"') do (
    set "LINE=%%A"
    setlocal enabledelayedexpansion
    set "LINE=!LINE:PUT_PCAPPLUSPLUS_HOME_HERE=%cd%!"
	set "LINE=!LINE:PUT_PCAP_SDK_HOME_HERE=%PCAP_SDK_HOME%!"
	set "LINE=!LINE:PUT_PTHREAD_HOME_HERE=%PTHREAD_HOME%!"
    echo !LINE!
    endlocal
))>pcpp_temp.xml

move /Y pcpp_temp.xml %VS_PROJ_DIR%\%VS_PROPERTY_SHEET% >nul


:: find Windows SDK version
set WindowsTargetPlatformVersion=8.1
call mk\vs\find-latest-win-sdk.bat

:: set default VS params
set ToolsVersion=14.0
set PlatformToolset=v140

:: set VS2015 params
if "%VS_VERSION%"=="vs2015" ( 
	set ToolsVersion=14.0
	set PlatformToolset=v140
)

:: set VS2017 params
if "%VS_VERSION%"=="vs2017" ( 
	set ToolsVersion=15.0
	set PlatformToolset=v141
)

:: set VS2019 params
if "%VS_VERSION%"=="vs2019" ( 
	set ToolsVersion=Current
	set PlatformToolset=v142
)

:: go over all vcxproj template files and set the project params according to the requested VS version
:: create vcxproj files and copy them to the VS project directory
setlocal enabledelayedexpansion
set PROJ_LIST_LOCAL=
for %%P in (mk\vs\*.vcxproj.template) do (
	set "TEMPALTE_PROJ_PATH=%%P"
	set "TEMPLATE_PROJ_FILENAME=%%~nxP"
	set "PROJ_NAME=!TEMPLATE_PROJ_FILENAME:.template=!"
	set PROJ_LIST_LOCAL=!PROJ_LIST_LOCAL!, !PROJ_NAME!

	(for /F "tokens=* delims=" %%A in ('type "!TEMPALTE_PROJ_PATH!"') do (
		set "LINE=%%A"
		set "LINE=!LINE:PUT_TOOLS_VERSION_HERE=%ToolsVersion%!"
		set "LINE=!LINE:PUT_WIN_TARGET_PLATFORM_HERE=%WindowsTargetPlatformVersion%!"
		set "LINE=!LINE:PUT_PLATORM_TOOLSET_HERE=%PlatformToolset%!"
		echo !LINE!
	))>pcpp_temp.xml

	move /Y pcpp_temp.xml %VS_PROJ_DIR%\!PROJ_NAME! >nul
)
endlocal & set PROJ_LIST=%PROJ_LIST_LOCAL%

:: copy solution, vcxproj.filters, and git info fetch files to VS project directory
xcopy /Y /Q mk\vs\*.sln %VS_PROJ_DIR%\ >nul
xcopy /Y /Q mk\vs\*.vcxproj.filters %VS_PROJ_DIR%\ >nul
xcopy /Y /Q mk\vs\fetch-git-info.bat %VS_PROJ_DIR%\ >nul
xcopy /Y /Q mk\vs\GitInfoPropertySheet.props %VS_PROJ_DIR%\ >nul

:: configuration completed
echo.
echo PcapPlusPlus Visual Studio configuration is complete. Files created (or modified): %VS_PROPERTY_SHEET%%PROJ_LIST%

:: exit script
exit /B 0


:: -------------------------------------------------------------------
:: an implementation of getopt for Windows and specifically for PcapPlusPlus
:: this "function" takes as paramters all command-line arguments given by the user who runs the script
:: then it parses the command-line arguments and calls switch cases per argument
:: it returns with the following exit codes:
::   - exit code 0 if arguments were parsed ok
::   - exit code 1 if an unknown argument was given or none arguments were given at all
::   - exit code 2 if a required parameter was not provided for one of the switches (for example: -g instead of -g <NUM>)
::   - exit code 3 if one of the command-line arguments asked to exit the script (for example the -h switch displays help and exits)
:GETOPT
:: if no arguments were passed exit with error code 1
if "%1"=="" call :GETOPT_ERROR "No parameters provided" & exit /B 1

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
	:: verify the MSYS dir provided by the user exists. If not, exit with error code 3, meaning ask the caller to exit the script
	if not exist %2\ call :GETOPT_ERROR "pthreads-win32 directory '%2' does not exist" & exit /B 3
	:: if all went well, set the PTHREAD_HOME variable with the directory given by the user
	set PTHREAD_HOME=%2
	:: notify GETOPT this switch has a parameter
	set HAS_PARAM=1
	:: exit ok
	exit /B 0

:: handling -w or --pcap-sdk switches
:CASE-w
:CASE--pcap-sdk
	:: this argument must have a parameter. If no parameter was found goto GETOPT_REQUIRED_PARAM and exit
	if "%2"=="" goto GETOPT_REQUIRED_PARAM %1
	:: verify the WinPcap/Npcap SDK dir provided by the user exists. If not, exit with error code 3, meaning ask the caller to exit the script
	if not exist %2\ call :GETOPT_ERROR "WinPcap/Npcap SDK directory '%2' does not exist" & exit /B 3
	:: if all went well, set the PCAP_SDK_HOME variable with the directory given by the user
	set PCAP_SDK_HOME=%2
	:: notify GETOPT this switch has a parameter
	set HAS_PARAM=1
	:: exit ok
	exit /B 0

:: handling -v or --vs-version switches
:CASE-v
:CASE--vs-version
	:: this argument must have a parameter. If no parameter was found goto GETOPT_REQUIRED_PARAM and exit
	if "%2"=="" goto GETOPT_REQUIRED_PARAM %1
	:: verify the VS version provided is one of the supported versions
	if "%2" NEQ "vs2015" if "%2" NEQ "vs2017" if "%2" NEQ "vs2019" call :GETOPT_ERROR "Visual Studio version must be one of: vs2015, vs2017, vs2019" & exit /B 3
	:: if all went well, set the VS_VERSION variable
	set VS_VERSION=%2
	:: notify GETOPT this switch has a parameter
	set HAS_PARAM=1
	:: exit ok
	exit /B 0

:: a required parameter error case, may get to here if a parameter was missing for a certain switch
:: the parameter for this "function" is the switch that didn't have the parameter
:GETOPT_REQUIRED_PARAM
	:: print the error message
	echo Required parameter not provided for switch "%1"
	:: exit with error code 2, meaining switch is missing a parameter
	exit /B 2

:: both switch cases and getopt may get to here if there was an error that needs to be reported to the user
:: calling this "function" has one parameter which is the error to print to the user
:GETOPT_ERROR
	:: reset error level
	VER > NUL # reset ERRORLEVEL
	:: print the error as was provided by the user. The %~1 removes quotes if were given
	echo %~1
	:: exit with error code 1
	exit /B 1

:: getopt finished successfully, exit ok
:GETOPT_END
	exit /B 0


:: -------------------------------------------------------------------
:: a "function" that implements the wizard mode which reads MinGW home and WinPcap/Npcap SDK by displaying a wizard for the user
:READ_PARAMS_FROM_USER

echo Choose Visual Studio version.
echo.
:while0
:: ask the user to type VS version
set /p VS_VERSION=     Currently supported options are: vs2015, vs2017 or vs2019: %=%
if "%VS_VERSION%" NEQ "vs2015" if "%VS_VERSION%" NEQ "vs2017" if "%VS_VERSION%" NEQ "vs2019" (echo Please choose one of "vs2015", "vs2017", "vs2019" && goto while0)

echo.
echo.

:: get WinPcap/Npcap SDK location from user and verify it exists
echo WinPcap or Npcap SDK is required for compiling PcapPlusPlus.
echo For downloading WinPcap SDK (developer's pack) please go to https://www.winpcap.org/devel.htm
echo For downloading Npcap SDK please go to https://nmap.org/npcap/#download
echo.
:while1
:: ask the user to type WinPcap/Npcap SDK dir
set /p PCAP_SDK_HOME=    Please specify WinPcap/Npcap SDK path: %=%
:: if input dir doesn't exist print an error to the user and go back to previous line
if not exist "%PCAP_SDK_HOME%"\ (echo Directory does not exist!! && goto while1)

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
if not exist "%PTHREAD_HOME%"\ (echo Directory does not exist!! && goto while2)


:: both directories were read correctly, return to the caller

exit /B 0


:: -------------------------------------------------------------------
:: a "function" that prints help information for this script
:HELP
echo.
echo Help documentation for %~nx0
echo This script has 2 modes of operation:
echo   1) Without any switches. In this case the script will guide you through using wizards
echo   2) With switches, as described below
echo.
echo Basic usage: %~nx0 [-h] -v VS_VERSION -p PTHREADS_WIN32_DIR -w PCAP_SDK_DIR
echo.
echo The following switches are recognized:
echo -v^|--vs-version      --Set Visual Studio version to configure. Must be one of: vs2015, vs2017, vs2019
echo -p^|--pthreads-home   --Set pthreads-win32 home directory
echo -w^|--pcap-sdk        --Set WinPcap/Npcap SDK directory
echo -h^|--help            --Display this help message and exits. No further actions are performed
echo.
:: done printing, exit
exit /B 0