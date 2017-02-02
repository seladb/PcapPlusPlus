set compiler=vs2015

set /p LATEST_RELEASE=<Deploy\latest_release.version
set DIST_DIR_NAME=PcapPlusPlus-%LATEST_RELEASE%-windows-%compiler%

move Dist %DIST_DIR_NAME%

copy Deploy\README.release.win.vs2015 %DIST_DIR_NAME%\README.release
mkdir %DIST_DIR_NAME%\ExampleProject
xcopy mk\vs2015\ExampleProject %DIST_DIR_NAME%\ExampleProject /E
xcopy Deploy\PcapPlusPlusPropertySheet.props %DIST_DIR_NAME%\ExampleProject /Y

7z a -r %DIST_DIR_NAME%.zip %DIST_DIR_NAME%\

curl --upload-file %DIST_DIR_NAME%.zip https://transfer.sh/%DIST_DIR_NAME%.zip