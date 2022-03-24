#!/bin/bash

set -e

SCRIPT_FILEPATH=$0
SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)

COLOR_RED='\033[0;31m'          # Red
COLOR_GREEN='\033[0;32m'        # Green
COLOR_PURPLE='\033[0;35m'       # Purple
COLOR_OFF='\033[0m'             # Reset

exit_with_error() {
    printf '%b\n' "${COLOR_RED}$*${COLOR_OFF}" >&2
    exit 1
}

is_integer () {
    case "${1#[+-]}" in
        (*[!0123456789]*) return 1 ;;
        ('')              return 1 ;;
        (*)               return 0 ;;
    esac
}

#########################################################################################

help() {
    printf '%b\n' "
${COLOR_PURPLE}Usage:${COLOR_OFF}

${COLOR_GREEN}$SCRIPT_FILEPATH${COLOR_OFF}
${COLOR_GREEN}$SCRIPT_FILEPATH -h${COLOR_OFF}
${COLOR_GREEN}$SCRIPT_FILEPATH --help${COLOR_OFF}
    show help of this script.

${COLOR_GREEN}$SCRIPT_FILEPATH <OPTION>...${COLOR_OFF}
    ${COLOR_GREEN}--ndk-path <ANDROID-NDK-ROOT>${COLOR_OFF}
        specify the root path of Android NDK, for example: '/opt/Android/Sdk/ndk/23.1.7779620'

    ${COLOR_GREEN}--target <ANDROID-ABI>${COLOR_OFF}
        specify the android abi, value must be one of 'arm64-v8a', 'armeabi-v7a', 'x86', 'x86_64'.

    ${COLOR_GREEN}--api <ANDROID-API-LEVEL>${COLOR_OFF}
        specify the android api level. value must be between 21 and 30. If not provided, the default value is 29.

    ${COLOR_GREEN}--libpcap-include-dir <DIR>${COLOR_OFF}
        specify the libpcap header files directory

    ${COLOR_GREEN}--libpcap-lib-dir <DIR>${COLOR_OFF}
        specify the libpcap pre compiled lib directory. Please make sure libpcap was compiled with the same architecture and API level

${COLOR_PURPLE}Examples:${COLOR_OFF}

${COLOR_GREEN}./configure-android.sh${COLOR_OFF}

${COLOR_GREEN}./configure-android.sh -h${COLOR_OFF}

${COLOR_GREEN}./configure-android.sh --help${COLOR_OFF}

${COLOR_GREEN}./configure-android.sh --ndk-path /opt/Android/sdk/ndk/23.1.7779620 --target armeabi-v7a --api 21 --libpcap-include-dir ~/libpcap/armeabi-v7a/include --libpcap-lib-dir ~/libpcap/armeabi-v7a/lib${COLOR_OFF}
"
}

#########################################################################################

printf '%b\n' "${COLOR_PURPLE}
******************************************
PcapPlusPlus Android configuration script
******************************************
${COLOR_OFF}"

case $1 in
    ''|-h|--help) help; exit
esac

unset ANDROID_NDK_ROOT
unset ANDROID_API_LEVEL

unset TARGET_TRIPLE

unset LIBPCAP_INCLUDE_DIR
unset LIBPCAP_LIBRARY_DIR

while [ -n "$1" ]
do
    case "$1" in
        --ndk-path)
            if [ -d "$2" ] ; then
                ANDROID_NDK_ROOT=$2
                shift 2
            else
                exit_with_error "--ndk-path PATH, PATH is not specified."
            fi
            ;;
        --target)
            case $2 in
                armeabi-v7a) TARGET_TRIPLE='armv7a-linux-androideabi' ;;
                arm64-v8a)   TARGET_TRIPLE='aarch64-linux-android'    ;;
                x86)         TARGET_TRIPLE='i686-linux-android'       ;;
                x86_64)      TARGET_TRIPLE='x86_64-linux-android'     ;;
                *) exit_with_error "--target TARGET, TARGET must be one of 'arm64-v8a', 'armeabi-v7a', 'x86', 'x86_64'"
            esac
            shift 2
            ;;
        --api)
            is_integer "$2" || exit_with_error "--api API, API must be a integer."
            if [ "$2" -ge 21 ] && [ "$2" -le 30 ] ; then
                ANDROID_API_LEVEL=$2
                shift 2
            else
                exit_with_error "--api API, API must be between 21 and 30."
            fi
            ;;
        --libpcap-include-dir)
            LIBPCAP_INCLUDE_DIR=$2
            shift 2
            ;;
        --libpcap-lib-dir)
            LIBPCAP_LIBRARY_DIR=$2
            shift 2
            ;;
        *)  exit_with_error "Unrecognized option: $1"
    esac
done

if [ -z "$ANDROID_NDK_ROOT" ] ; then
    exit_with_error "Please specify the Android NDK root path via --ndk-path PATH"
fi

if [ -z "$ANDROID_API_LEVEL" ] ; then
    ANDROID_API_LEVEL=29
fi

if [ -z "$TARGET_TRIPLE" ] ; then
    exit_with_error "Please specify the target via --target TARGET"
fi

if [ -z "$LIBPCAP_INCLUDE_DIR" ]; then
    exit_with_error "Please specify the directory of libpcap header files via --libpcap-include-dir DIR"
fi

if [ -z "$LIBPCAP_LIBRARY_DIR" ]; then
    exit_with_error "Please specify the directory of libpcap binary that matches the specified target via --libpcap-lib-dir DIR"
fi

#########################################################################################

unset BUILD_MACHINE_OS_TYPE
unset BUILD_MACHINE_OS_ARCH

BUILD_MACHINE_OS_TYPE=$(uname | tr A-Z a-z)
BUILD_MACHINE_OS_ARCH=$(uname -m)

ANDROID_TOOLCHAIN=$ANDROID_NDK_ROOT/toolchains/llvm/prebuilt/$BUILD_MACHINE_OS_TYPE-$BUILD_MACHINE_OS_ARCH

#########################################################################################

cat <<EOF
Build machine OS type: $BUILD_MACHINE_OS_TYPE
Build machine OS arch: $BUILD_MACHINE_OS_ARCH

Android NDK root:  $ANDROID_NDK_ROOT
Anrdoid API level: $ANDROID_API_LEVEL
Android toolchain path: $ANDROID_TOOLCHAIN

Target triple: $TARGET_TRIPLE

libpcap include dir: $LIBPCAP_INCLUDE_DIR
libpcap library dir: $LIBPCAP_LIBRARY_DIR
EOF

#########################################################################################

unset TEMP_DIR
unset TEMP_CONFIG_FILE

TEMP_DIR=$(mktemp -d)
TEMP_CONFIG_FILE="$TEMP_DIR/config.mk"

cat > "$TEMP_CONFIG_FILE" <<EOF
PCAPPLUSPLUS_HOME   := $SCRIPT_DIR
ANDROID_TARGET      := $TARGET_TRIPLE$ANDROID_API_LEVEL
ANDROID_TOOLCHAIN   := $ANDROID_TOOLCHAIN
EOF

#########################################################################################

PCAPPLUSPLUS_MK="$SCRIPT_DIR/mk/PcapPlusPlus.mk"

cp -f "$TEMP_CONFIG_FILE"                       "$PCAPPLUSPLUS_MK"
cat "$SCRIPT_DIR/mk/PcapPlusPlus.mk.common"  >> "$PCAPPLUSPLUS_MK"
cat "$SCRIPT_DIR/mk/PcapPlusPlus.mk.android" >> "$PCAPPLUSPLUS_MK"

cat >> "$PCAPPLUSPLUS_MK" <<EOF
LIBPCAP_INCLUDE_DIR := $LIBPCAP_INCLUDE_DIR
PCAPPP_INCLUDES += -I\$(LIBPCAP_INCLUDE_DIR)
LIBPCAP_LIB_DIR := $LIBPCAP_LIBRARY_DIR
PCAPPP_LIBS_DIR += -L\$(LIBPCAP_LIB_DIR)
EOF

#########################################################################################

PLATFORM_MK="$SCRIPT_DIR/mk/platform.mk"

cp -f "$TEMP_CONFIG_FILE"                    "$PLATFORM_MK"
cat "$SCRIPT_DIR/mk/platform.mk.android"  >> "$PLATFORM_MK"

#########################################################################################

printf '%b\n' "
${COLOR_GREEN}PcapPlusPlus Android configuration is complete.${COLOR_OFF}

configurations is written to :
    - $PLATFORM_MK
    - $PCAPPLUSPLUS_MK
"
