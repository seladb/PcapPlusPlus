set compiler=vs2015

set /p LATEST_RELEASE=<Deploy\latest_release.version
set DIST_DIR_NAME=PcapPlusPlus-%LATEST_RELEASE%-windows-%compiler%

move Dist %DIST_DIR_NAME%

copy Deploy\README.release.win.vs2015 %DIST_DIR_NAME%\README.release
mkdir %DIST_DIR_NAME%\ExampleProject
xcopy Examples\ArpSpoofing-VS2015-Project %DIST_DIR_NAME%\ExampleProject /E
xcopy Deploy\PcapPlusPlusPropertySheet.props %DIST_DIR_NAME%\ExampleProject /Y
xcopy Deploy\ArpSpoofing.vcxproj %DIST_DIR_NAME%\ExampleProject /Y
del /s /q %DIST_DIR_NAME%\ExampleProject\Debug
del /s /q %DIST_DIR_NAME%\ExampleProject\Release
del /s /q %DIST_DIR_NAME%\ExampleProject\x64
rmdir /s /q %DIST_DIR_NAME%\ExampleProject\Debug
rmdir /s /q %DIST_DIR_NAME%\ExampleProject\Release
rmdir /s /q %DIST_DIR_NAME%\ExampleProject\x64

7z a -r %DIST_DIR_NAME%.zip %DIST_DIR_NAME%\

curl --upload-file %DIST_DIR_NAME%.zip https://transfer.sh/%DIST_DIR_NAME%.zip