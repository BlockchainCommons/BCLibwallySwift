# BCLibWallySwift

## DEPRECATED

⚠️ This library has now been deprecated in favor of [BCSwiftFoundation](https://github.com/blockchaincommons/BCSwiftFoundation), which is an easy-to-include and maintain Swift package that uses the XCFramework built using the special build system of [BCSwiftWally](https://github.com/blockchaincommons/BCSwiftWally), which is a thin Swift-based wrapper around libwallycore.

--

Opinionated Swift wrapper around [LibWally](https://github.com/ElementsProject/libwally-core), a collection of useful primitives for cryptocurrency wallets.

This is a fork of [LibWally Swift](https://github.com/blockchain/libwally-swift). It has a new build system for building a universal XCFramework for use with MacOSX, Mac Catalyst, iOS devices, and the iOS simulator across Intel and Apple Silicon (ARM).

Also supports particular enhancements used by Blockchain Commons from our fork of libwally-core: [bc-libwally-core](https://github.com/blockchaincommons/bc-libwally-core), in the [bc-maintenance](https://github.com/BlockchainCommons/bc-libwally-core/tree/bc-maintenance) branch.

## Dependencies

```sh
$ brew install autoconf autogen gsed
```

## Build

```sh
$ git clone https://github.com/blockchaincommons/BCLibWallySwift.git
$ cd BCLibWallySwift
$ ./build.sh
```

The resulting frameworks are `build/CLibwally.xcframework` and `build/LibWally.xcframework`. Add both to your project.

## Usage

These examples were outdated and have been removed.
