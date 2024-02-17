:: Install WinPcap Runtime
git submodule update --init --recursive
:: use our fork to prevent the repository from being deleted
git clone https://github.com/PcapPlusPlus/winpcap-installer
winpcap-installer\winpcap-truesight-meter-4.1.3.exe /S
rmdir winpcap-installer /s /q

:: Install WinPcap SDK
git clone https://github.com/seladb/PcapPlusPlus-Deploy
7z x PcapPlusPlus-Deploy\Packages\WpdPack_4_1_2.zip -oC:\
rmdir PcapPlusPlus-Deploy /s /q
