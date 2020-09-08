#!/usr/bin/env sh
set -e # abort if any command fails

MIN_IOS_VERSION="13.6"
MIN_MAC_VERSION="10.15"
PROJ_ROOT=${PWD}
BUILD_ROOT=${PROJ_ROOT}/build
# CLIBWALLY_ROOT=${PROJ_ROOT}/CLibWally
LIBWALLY_ROOT=${PROJ_ROOT}/LibWally
OUTPUT_DIR=${BUILD_ROOT}/fat
LOG_FILE=/dev/null

build_init()
{
  LIB_NAME=$1
  PLATFORM=$2
  ARCH=$3
  TARGET=$4
  HOST=$5
  SDK=$6
  BITCODE=$7
  VERSION=$8
  SDK_PATH=`xcrun -sdk ${SDK} --show-sdk-path`
  PREFIX=${BUILD_ROOT}/${PLATFORM}-${ARCH}/${LIB_NAME}

  export CFLAGS="-O3 -arch ${ARCH} -isysroot ${SDK_PATH} ${BITCODE} ${VERSION} -target ${TARGET} -Wno-overriding-t-option"
  export CXXFLAGS="-O3 -arch ${ARCH} -isysroot ${SDK_PATH} ${BITCODE} ${VERSION} -target ${TARGET} -Wno-overriding-t-option"
  export LDFLAGS="-arch ${ARCH} ${BITCODE}"
  export CC="$(xcrun --sdk ${SDK} -f clang) -arch ${ARCH} -isysroot ${SDK_PATH}"
  export CXX="$(xcrun --sdk ${SDK} -f clang++) -arch ${ARCH} -isysroot ${SDK_PATH}"
}

build_clibwally()
{
  build_init libwally $@

  pushd ${PROJ_ROOT}/libwally-core

  cp ${PROJ_ROOT}/CLibWally.modulemap include/module.modulemap

  ./tools/autogen.sh
  PKG_CONFIG_ALLOW_CROSS=1 \
  PKG_CONFIG_PATH=$PREFIX/lib/pkgconfig \
  ./configure \
    --disable-shared \
    --host=${HOST} \
    --enable-static \
    --prefix=${PREFIX}

  make clean
  make install
  make clean

  popd

  # Remove unused headers and add the modulemap
  pushd ${PREFIX}/include
  rm secp256k1*.h
  rm wally_elements.h
  rm wally.hpp
  cp ${PROJ_ROOT}/CLibWally.modulemap module.modulemap
  popd
}

build_clibwally_ios_device()
{
  IOS_ARM64_PARAMS=("ios" "arm64" "aarch64-apple-ios" "arm-apple-darwin" "iphoneos" "-fembed-bitcode" "-mios-version-min=${MIN_IOS_VERSION}")
  build_clibwally ${IOS_ARM64_PARAMS[@]}
}

build_clibwally_ios_catalyst()
{
  MAC_CATALYST_X86_64_PARAMS=("mac-catalyst" "x86_64" "x86_64-apple-ios13.0-macabi" "x86_64-apple-darwin" "macosx" "-fembed-bitcode" "-mmacosx-version-min=${MIN_MAC_VERSION}") # This is the build that runs under Catalyst
  build_clibwally ${MAC_CATALYST_X86_64_PARAMS[@]}
}

build_clibwally_ios_simulator()
{
  IOS_SIMULATOR_X86_64_PARAMS=("ios-simulator" "x86_64" "x86_64-apple-ios" "x86_64-apple-darwin" "iphonesimulator" "-fembed-bitcode-marker" "-mios-simulator-version-min=${MIN_IOS_VERSION}")
  build_clibwally ${IOS_SIMULATOR_X86_64_PARAMS[@]}
}

build_clibwally_all()
(
  build_clibwally_ios_device
  build_clibwally_ios_catalyst
  build_clibwally_ios_simulator
)

build_clibwally_xcframework()
{
  rm -rf "${BUILD_ROOT}/CLibWally.xcframework"
  xcodebuild -create-xcframework \
    -library "${BUILD_ROOT}/ios-arm64/libwally/lib/libwallycore.a" -headers "${BUILD_ROOT}/ios-arm64/libwally/include/" \
    -library "${BUILD_ROOT}/mac-catalyst-x86_64/libwally/lib/libwallycore.a" -headers "${BUILD_ROOT}/mac-catalyst-x86_64/libwally/include/" \
    -library "${BUILD_ROOT}/ios-simulator-x86_64/libwally/lib/libwallycore.a" -headers "${BUILD_ROOT}/ios-simulator-x86_64/libwally/include/" \
    -output "${BUILD_ROOT}/CLibWally.xcframework"
}

build_libwally_framework()
{
  XC_ARCH=$1
  XC_BUILD_DIR_NAME=$2
  XC_SDK=$3
  XC_CATALYST=$4
  XC_VERSION=$5

  XC_PROJECT=${LIBWALLY_ROOT}/LibWally.xcodeproj
  XC_SCHEME=LibWally
  XC_BUILD_DIR=${BUILD_ROOT}/${XC_BUILD_DIR_NAME}
  XC_ARCHIVE_PATH=${XC_BUILD_DIR}/LibWally.xcarchive
  rm -rf ${ARCHIVE_PATH}
  xcodebuild clean archive \
    -project ${XC_PROJECT} \
    -scheme ${XC_SCHEME} \
    -archivePath ${XC_ARCHIVE_PATH} \
    -sdk ${XC_SDK} \
    ${XC_VERSION} \
    ONLY_ACTIVE_ARCH=YES \
    ARCHS=${XC_ARCH} \
    SKIP_INSTALL=NO \
    BUILD_LIBRARIES_FOR_DISTRIBUTION=YES \
    SUPPORTS_MACCATALYST=${XC_CATALYST} \
    FRAMEWORK_SEARCH_PATHS="${BUILD_ROOT}/"
}

build_libwally_frameworks()
{
  build_libwally_framework arm64 ios-arm64 iphoneos NO "IPHONEOS_DEPLOYMENT_TARGET=${MIN_IOS_VERSION}"
  build_libwally_framework x86_64 mac-catalyst-x86_64 macosx YES "MACOSX_DEPLOYMENT_TARGET=${MIN_MAC_VERSION}"
  build_libwally_framework x86_64 ios-simulator-x86_64 iphonesimulator NO "IPHONEOS_DEPLOYMENT_TARGET=${MIN_IOS_VERSION}"

  # build_clibwally_framework armv7 ios-armv7 iphoneos NO
  # build_clibwally_framework i386 ios-simulator-i386 iphonesimulator NO
}

build_libwally_xcframework()
{
  FRAMEWORK_PATH=LibWally.xcarchive/Products/Library/Frameworks/LibWally.framework

  rm -rf ${BUILD_ROOT}/LibWally.xcframework
  xcodebuild -create-xcframework \
  -framework ${BUILD_ROOT}/ios-arm64/${FRAMEWORK_PATH} \
  -framework ${BUILD_ROOT}/mac-catalyst-x86_64/${FRAMEWORK_PATH} \
  -framework ${BUILD_ROOT}/ios-simulator-x86_64/${FRAMEWORK_PATH} \
  -output ${BUILD_ROOT}/LibWally.xcframework
}

build_clibwally_all
build_clibwally_xcframework
build_libwally_frameworks
build_libwally_xcframework
