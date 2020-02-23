appveyor DownloadFile https://nmap.org/npcap/dist/npcap-0.96.exe
npcap-0.96.exe /S /winpcap_mode
xcopy C:\Windows\System32\Npcap\wpcap.dll C:\Windows\System32
xcopy C:\Windows\SysWOW64\Npcap\wpcap.dll C:\Windows\SysWOW64
appveyor DownloadFile https://nmap.org/npcap/dist/npcap-sdk-1.04.zip
mkdir C:\Npcap-sdk
7z x .\npcap-sdk-1.04.zip -oC:\Npcap-sdk