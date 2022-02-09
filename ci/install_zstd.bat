set ZSTD_VERSION=1.5.2
set ZSTD_NAME=zstd-v%ZSTD_VERSION%
set ZSTD_PLATFORM=win64
if "%1"=="x86" set ZSTD_PLATFORM=win32
set ZSTD_FILE_NAME=%ZSTD_NAME%-%ZSTD_PLATFORM%.zip

curl -L https://github.com/facebook/zstd/releases/download/v%ZSTD_VERSION%/%ZSTD_FILE_NAME% --output %ZSTD_FILE_NAME%
7z x %ZSTD_FILE_NAME% -o"C:\zstd_tmp" && move "C:\zstd_tmp\%ZSTD_NAME%-%ZSTD_PLATFORM%" "C:\zstd"
