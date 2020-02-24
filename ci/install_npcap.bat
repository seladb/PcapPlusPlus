appveyor DownloadFile https://nmap.org/npcap/dist/npcap-0.96.exe
echo DONE DONWLOADING Npcap
npcap-0.96.exe /S /winpcap_mode
echo DONE INSTALLING
xcopy C:\Windows\System32\Npcap\*.dll C:\Windows\System32
echo DONE COPING System32
xcopy C:\Windows\SysWOW64\Npcap\*.dll C:\Windows\SysWOW64
echo DONE COPING SysWOW64
appveyor DownloadFile https://nmap.org/npcap/dist/npcap-sdk-1.04.zip
echo DONE DONWLOADING Npcap SDK
mkdir C:\Npcap-sdk
echo DONE MKDIR
7z x .\npcap-sdk-1.04.zip -oC:\Npcap-sdk
echo DONE EXTRACTING