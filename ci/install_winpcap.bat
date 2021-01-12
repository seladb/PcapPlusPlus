git submodule update --init --recursive
git clone https://github.com/mfontanini/winpcap-installer.git
cd winpcap-installer
winpcap-boundary-meter-4.1.3.exe /S
cd ..
curl https://www.winpcap.org/install/bin/WpdPack_4_1_2.zip --output WpdPack_4_1_2.zip
7z x .\WpdPack_4_1_2.zip -oc:\