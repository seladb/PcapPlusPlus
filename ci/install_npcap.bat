set NPCAP_OEM_CREDENTIALS_DEFINED=0
if defined NPCAP_USERNAME set /A NPCAP_OEM_CREDENTIALS_DEFINED=NPCAP_OEM_CREDENTIALS_DEFINED+1
if defined NPCAP_PASSWORD set /A NPCAP_OEM_CREDENTIALS_DEFINED=NPCAP_OEM_CREDENTIALS_DEFINED+1

if "%NPCAP_OEM_CREDENTIALS_DEFINED%"=="2" (
	echo Using Npcap OEM version
	set NPCAP_FILE=npcap-0.9988-oem.exe
	curl --digest --user %NPCAP_USERNAME%:%NPCAP_PASSWORD% https://nmap.org/npcap/oem/dist/%NPCAP_FILE% --output %NPCAP_FILE%
) else (
	echo Using Npcap free version"
	set NPCAP_FILE=npcap-0.96.exe
	appveyor DownloadFile https://nmap.org/npcap/dist/%NPCAP_FILE%
)

%NPCAP_FILE% /S /winpcap_mode
appveyor DownloadFile https://nmap.org/npcap/dist/npcap-sdk-1.04.zip
mkdir C:\Npcap-sdk
7z x .\npcap-sdk-1.04.zip -oC:\Npcap-sdk