set NPCAP_OEM_FILE=npcap-0.9988-oem.exe
curl --digest --user %NPCAP_USERNAME%:%NPCAP_PASSWORD% https://nmap.org/npcap/oem/dist/%NPCAP_OEM_FILE% --output %NPCAP_OEM_FILE%
%NPCAP_OEM_FILE% /S /winpcap_mode
appveyor DownloadFile https://nmap.org/npcap/dist/npcap-sdk-1.04.zip
mkdir C:\Npcap-sdk
7z x .\npcap-sdk-1.04.zip -oC:\Npcap-sdk