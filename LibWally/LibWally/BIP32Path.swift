//
//  BIP32.swift
//  BIP32 
//
//  Created by Sjors on 29/05/2019.
//  Copyright © 2019 Blockchain. Distributed under the MIT software
//  license, see the accompanying file LICENSE.md

import Foundation
import CLibWally

public struct BIP32Path : Equatable {

    public enum DerivationStep : Equatable {
        // max 2^^31 - 1: enforced by the BIP32Path initializer
        case normal(UInt32)
        case hardened(UInt32)

        public var isHardened: Bool {
            switch self {
                case .normal(_):
                    return false
                case .hardened(_):
                    return true
            }
        }
    }

    public let components: [DerivationStep]
    let rawPath: [UInt32]
    let isRelative: Bool
    
    public init(_ rawPath: [UInt32], isRelative: Bool) throws {
        var components: [DerivationStep] = []
        for index in rawPath {
            if index < BIP32_INITIAL_HARDENED_CHILD {
                components.append(DerivationStep.normal(index))
            } else {
                components.append(DerivationStep.hardened(index - BIP32_INITIAL_HARDENED_CHILD))
            }
        }
        try self.init(components, isRelative:isRelative)
    }
    
    public init(_ components: [DerivationStep], isRelative: Bool) throws {
        var rawPath: [UInt32] = []
        self.isRelative = isRelative

        for component in components {
            switch component {
            case .normal(let index):
                if index >= BIP32_INITIAL_HARDENED_CHILD {
                    throw LibWallyError("Invalid index in path.")
                }
                rawPath.append(index)
            case .hardened(let index):
                if index >= BIP32_INITIAL_HARDENED_CHILD {
                    throw LibWallyError("Invalid index in path.")
                }
                rawPath.append(BIP32_INITIAL_HARDENED_CHILD + index)
            }
        }
        self.components = components
        self.rawPath = rawPath
    }
    
    public init(_ component: DerivationStep, isRelative: Bool = true) throws {
        try self.init([component], isRelative: isRelative)
    }
    
    public init(_ index: Int, isRelative: Bool = true) throws {
        try self.init([.normal(UInt32(index))], isRelative: isRelative)
    }
    
    public init(_ description: String) throws {
        guard description.count > 0 else {
            throw LibWallyError("Invalid path.")
        }
        let isRelative = description.prefix(2) != "m/"
        var tmpComponents: [DerivationStep] = []

        for component in description.split(separator: "/") {
            if component == "m" { continue }
            let index: UInt32? = UInt32(component)
            if let i = index {
                tmpComponents.append(.normal(i))
            } else if component.suffix(1) == "h" || component.suffix(1) == "'" {
                let indexHardened: UInt32? = UInt32(component.dropLast(1))
                if let i = indexHardened {
                    tmpComponents.append(.hardened(i))
                } else {
                    throw LibWallyError("Invalid path.")
                }
            } else {
                throw LibWallyError("Invalid path.")
            }
        }
        
        guard tmpComponents.count > 0 else {
            throw LibWallyError("Invalid path.")
        }
        do {
            try self.init(tmpComponents, isRelative: isRelative)
        } catch {
            throw LibWallyError("Invalid path.")
        }
    }
    
    public var description: String {
        var pathString = self.isRelative ? "" : "m/"
        for (index, item) in components.enumerated() {
            switch item {
            case .normal(let index):
                pathString += String(index)
            case .hardened(let index):
                pathString += String(index) + "h"
            }
            if index < components.endIndex - 1 {
                pathString += "/"
            }
        }
        return pathString
    }
    
    public func chop(_ depth: Int) throws -> BIP32Path {
        if depth > components.count {
            throw LibWallyError("Invalid depth.")
        }
        var newComponents = self.components
        newComponents.removeFirst(Int(depth))
        return try BIP32Path(newComponents, isRelative: true)
    }
    
}
