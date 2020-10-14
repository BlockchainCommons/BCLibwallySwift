#!/usr/bin/env sh
set -e # abort if any command fails

git submodule update --init

MIN_IOS_VERSION="13.6"
MIN_MAC_VERSION="10.15"
PROJ_ROOT=${PWD}
DEPS_ROOT=${PROJ_ROOT}/deps
BUILD_ROOT=${PROJ_ROOT}/build
LIBWALLY_ROOT=${PROJ_ROOT}/LibWally

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

finish_build_clibwally()
{
  # Remove unused headers and add the modulemap
  pushd ${PREFIX}/include
  rm secp256k1*.h
  rm wally_elements.h
  rm wally.hpp
  cp ${PROJ_ROOT}/CLibWally.modulemap module.modulemap
  popd
}

build_clibwally()
(
  build_init libwally $@

  pushd ${DEPS_ROOT}/libwally-core

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

  finish_build_clibwally
)

build_clibwally_native()
(
  LIB_NAME=libwally
  PLATFORM=$1
  ARCH=$2
  BITCODE=$3
  VERSION=$4
  PREFIX=${BUILD_ROOT}/${PLATFORM}-${ARCH}/${LIB_NAME}

  export CFLAGS="-O3 ${BITCODE} ${VERSION} -Wno-overriding-t-option"
  export CXXFLAGS="-O3 ${BITCODE} ${VERSION} -Wno-overriding-t-option"
  export LDFLAGS="${BITCODE}"

  pushd ${DEPS_ROOT}/libwally-core

  cp ${PROJ_ROOT}/CLibWally.modulemap include/module.modulemap

  ./tools/autogen.sh
  PKG_CONFIG_PATH=$PREFIX/lib/pkgconfig \
  ./configure \
    --disable-shared \
    --enable-static \
    --prefix=${PREFIX}

  make clean
  make install
  make clean

  popd

  finish_build_clibwally
)

 build_c_libraries()
(
  IOS_ARM64_PARAMS=("ios" "arm64" "aarch64-apple-ios" "arm-apple-darwin" "iphoneos" "-fembed-bitcode" "-mios-version-min=${MIN_IOS_VERSION}")
  MAC_CATALYST_X86_64_PARAMS=("mac-catalyst" "x86_64" "x86_64-apple-ios13.0-macabi" "x86_64-apple-darwin" "macosx" "-fembed-bitcode" "-mmacosx-version-min=${MIN_MAC_VERSION}")
  IOS_SIMULATOR_X86_64_PARAMS=("ios-simulator" "x86_64" "x86_64-apple-ios" "x86_64-apple-darwin" "iphonesimulator" "-fembed-bitcode-marker" "-mios-simulator-version-min=${MIN_IOS_VERSION}")
  MACOSX_X86_64_PARAMS=("macosx" "x86_64" "-fembed-bitcode" "-mmacosx-version-min=${MIN_MAC_VERSION}")

  build_clibwally ${IOS_ARM64_PARAMS[@]}
  build_clibwally ${MAC_CATALYST_X86_64_PARAMS[@]}
  build_clibwally ${IOS_SIMULATOR_X86_64_PARAMS[@]}
  build_clibwally_native ${MACOSX_X86_64_PARAMS[@]}
)

build_c_framework()
{
  rm -rf "${BUILD_ROOT}/CLibWally.xcframework"
  xcodebuild -create-xcframework \
    -library "${BUILD_ROOT}/ios-arm64/libwally/lib/libwallycore.a" -headers "${BUILD_ROOT}/ios-arm64/libwally/include/" \
    -library "${BUILD_ROOT}/mac-catalyst-x86_64/libwally/lib/libwallycore.a" -headers "${BUILD_ROOT}/mac-catalyst-x86_64/libwally/include/" \
    -library "${BUILD_ROOT}/ios-simulator-x86_64/libwally/lib/libwallycore.a" -headers "${BUILD_ROOT}/ios-simulator-x86_64/libwally/include/" \
    -library "${BUILD_ROOT}/macosx-x86_64/libwally/lib/libwallycore.a" -headers "${BUILD_ROOT}/macosx-x86_64/libwally/include/" \
    -output "${BUILD_ROOT}/CLibWally.xcframework"
}

build_swift_framework()
{
  XC_FRAMEWORK=$1
  XC_ARCH=$2
  XC_BUILD_DIR_NAME=$3
  XC_SDK=$4
  XC_PLATFORM_DIR=$5
  XC_CATALYST=$6
  XC_VERSION=$7
  XC_CONFIGURATION=Debug

  FRAMEWORK_ROOT=${PROJ_ROOT}/${XC_FRAMEWORK}

  XC_PROJECT=${FRAMEWORK_ROOT}/${XC_FRAMEWORK}.xcodeproj
  XC_SCHEME=${XC_FRAMEWORK}
  XC_DEST_BUILD_DIR=${BUILD_ROOT}/${XC_BUILD_DIR_NAME}
  XC_FRAMEWORK_DIR_NAME=${XC_FRAMEWORK}.framework
  rm -rf ${XC_DEST_BUILD_DIR}/${XC_FRAMEWORK_DIR_NAME}

  XC_ARGS="\
    -project ${XC_PROJECT} \
    -scheme ${XC_SCHEME} \
    -configuration ${XC_CONFIGURATION} \
    -sdk ${XC_SDK} \
    ${XC_VERSION} \
    ONLY_ACTIVE_ARCH=YES \
    ARCHS=${XC_ARCH} \
    SKIP_INSTALL=NO \
    BUILD_LIBRARIES_FOR_DISTRIBUTION=YES \
    SUPPORTS_MACCATALYST=${XC_CATALYST}"

  xcodebuild clean build ${XC_ARGS[@]}

  XC_BUILD_DIR=`
    xcodebuild ${XC_ARGS[@]} -showBuildSettings | grep -o '\<BUILD_DIR = .*' | cut -d ' ' -f 3
    `

  if [ $XC_PLATFORM_DIR == "NONE" ]
  then
    XC_FRAMEWORK_SOURCE_DIR=${XC_BUILD_DIR}/${XC_CONFIGURATION}
  else
    XC_FRAMEWORK_SOURCE_DIR=${XC_BUILD_DIR}/${XC_CONFIGURATION}-${XC_PLATFORM_DIR}
  fi

  cp -R "${XC_FRAMEWORK_SOURCE_DIR}/${XC_FRAMEWORK_DIR_NAME}" ${XC_DEST_BUILD_DIR}/

  xcodebuild clean ${XC_ARGS[@]}

  #echo diff -rq "${XC_FRAMEWORK_SOURCE_DIR}/${XC_FRAMEWORK_DIR_NAME}" "${XC_DEST_BUILD_DIR}/${XC_FRAMEWORK_DIR_NAME}"
}

build_swift_frameworks()
(
  IOS_ARM64_PARAMS=("arm64" "ios-arm64" "iphoneos" "iphoneos" "NO" "IPHONEOS_DEPLOYMENT_TARGET=${MIN_IOS_VERSION}")
  MAC_CATALYST_X86_64_PARAMS=("x86_64" "mac-catalyst-x86_64" "macosx" "maccatalyst" "YES" "MACOSX_DEPLOYMENT_TARGET=${MIN_MAC_VERSION}")
  IOS_SIMULATOR_X86_64_PARAMS=("x86_64" "ios-simulator-x86_64" "iphonesimulator" "iphonesimulator" "NO" "IPHONEOS_DEPLOYMENT_TARGET=${MIN_IOS_VERSION}")
  MACOSX_X86_64_PARAMS=("x86_64" "macosx-x86_64" "macosx" "NONE" "NO" "MACOSX_DEPLOYMENT_TARGET=${MIN_MAC_VERSION}")

  build_swift_framework LibWally ${IOS_ARM64_PARAMS[@]}
  build_swift_framework LibWally ${MAC_CATALYST_X86_64_PARAMS[@]}
  build_swift_framework LibWally ${IOS_SIMULATOR_X86_64_PARAMS[@]}
  build_swift_framework LibWally ${MACOSX_X86_64_PARAMS[@]}
)

build_swift_xcframework()
{
  FRAMEWORK_NAME=$1

  PLATFORM_FRAMEWORK_NAME=${FRAMEWORK_NAME}.framework
  XC_FRAMEWORK_NAME=${FRAMEWORK_NAME}.xcframework
  XC_FRAMEWORK_PATH=${BUILD_ROOT}/${XC_FRAMEWORK_NAME}

  rm -rf ${XC_FRAMEWORK_PATH}
  xcodebuild -create-xcframework \
  -framework ${BUILD_ROOT}/ios-arm64/${PLATFORM_FRAMEWORK_NAME} \
  -framework ${BUILD_ROOT}/mac-catalyst-x86_64/${PLATFORM_FRAMEWORK_NAME} \
  -framework ${BUILD_ROOT}/ios-simulator-x86_64/${PLATFORM_FRAMEWORK_NAME} \
  -framework ${BUILD_ROOT}/macosx-x86_64/${PLATFORM_FRAMEWORK_NAME} \
  -output ${XC_FRAMEWORK_PATH}

  # As of September 22, 2020, the step above is broken:
  # it creates unusable XCFrameworks; missing files like Modules/CryptoBase.swiftmodule/Project/x86_64-apple-ios-simulator.swiftsourceinfo
  # The frameworks we started with were fine. So we're going to brute-force replace the frameworks in the XCFramework with the originials.

  rm -rf ${XC_FRAMEWORK_PATH}/ios-arm64/${PLATFORM_FRAMEWORK_NAME}
  cp -R ${BUILD_ROOT}/ios-arm64/${PLATFORM_FRAMEWORK_NAME} ${XC_FRAMEWORK_PATH}/ios-arm64/

  rm -rf ${XC_FRAMEWORK_PATH}/ios-x86_64-maccatalyst/${PLATFORM_FRAMEWORK_NAME}
  cp -R ${BUILD_ROOT}/mac-catalyst-x86_64/${PLATFORM_FRAMEWORK_NAME} ${XC_FRAMEWORK_PATH}/ios-x86_64-maccatalyst/

  rm -rf ${XC_FRAMEWORK_PATH}/ios-x86_64-simulator/${PLATFORM_FRAMEWORK_NAME}
  cp -R ${BUILD_ROOT}/ios-simulator-x86_64/${PLATFORM_FRAMEWORK_NAME} ${XC_FRAMEWORK_PATH}/ios-x86_64-simulator/

  rm -rf ${XC_FRAMEWORK_PATH}/macos-x86_64/${PLATFORM_FRAMEWORK_NAME}
  cp -R ${BUILD_ROOT}/macosx-x86_64/${PLATFORM_FRAMEWORK_NAME} ${XC_FRAMEWORK_PATH}/macos-x86_64/
}

build_swift_xcframeworks()
(
  build_swift_xcframework LibWally
)

build_c_libraries
build_c_framework
build_swift_frameworks
build_swift_xcframeworks
