:: Install WinPcap Runtime
git submodule update --init --recursive
git clone https://github.com/mfontanini/winpcap-installer.git
winpcap-installer\winpcap-boundary-meter-4.1.3.exe /S
rmdir winpcap-installer /s /q

:: Install WinPcap SDK
git clone https://github.com/seladb/PcapPlusPlus-Deploy
7z x PcapPlusPlus-Deploy\Packages\WpdPack_4_1_2.zip -oC:\
rmdir PcapPlusPlus-Deploy /s /q
