set NPCAP_OEM_CREDENTIALS_DEFINED=0
if defined NPCAP_USERNAME set /A NPCAP_OEM_CREDENTIALS_DEFINED=NPCAP_OEM_CREDENTIALS_DEFINED+1
if defined NPCAP_PASSWORD set /A NPCAP_OEM_CREDENTIALS_DEFINED=NPCAP_OEM_CREDENTIALS_DEFINED+1

if "%NPCAP_OEM_CREDENTIALS_DEFINED%"=="2" (
	set NPCAP_FILE=npcap-1.60-oem.exe
) else (
	:: Silent mode is disabled for newer non-oem version
	set NPCAP_FILE=npcap-0.96.exe
)

if "%NPCAP_OEM_CREDENTIALS_DEFINED%"=="2" (
	echo Using Npcap OEM version %NPCAP_FILE%
	curl -L --digest --user %NPCAP_USERNAME%:%NPCAP_PASSWORD% https://npcap.com/oem/dist/%NPCAP_FILE% --output %NPCAP_FILE%
) else (
	echo Using Npcap free version %NPCAP_FILE%
	curl -L https://npcap.com/dist/%NPCAP_FILE% --output %NPCAP_FILE%
)

%NPCAP_FILE% /S /winpcap_mode

if not "%NPCAP_OEM_CREDENTIALS_DEFINED%"=="2" (
	xcopy C:\Windows\System32\Npcap\*.dll C:\Windows\System32
	xcopy C:\Windows\SysWOW64\Npcap\*.dll C:\Windows\SysWOW64
)

curl -L --connect-timeout 5 --max-time 10 --retry 5 --retry-delay 0 --retry-max-time 120 https://npcap.com/dist/npcap-sdk-1.12.zip --output npcap-sdk.zip
mkdir C:\Npcap-sdk
7z x .\npcap-sdk.zip -oC:\Npcap-sdk
