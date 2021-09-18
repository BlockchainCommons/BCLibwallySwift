//
//  DerivationPath.swift
//  LibWally
//
//  Created by Wolf McNally on 9/1/21.
//

import Foundation
@_implementationOnly import WolfBase

public struct DerivationStep : Equatable {
    public let index: Index
    public let isHardened: Bool
    
    public enum Index: Equatable {
        case childNum(UInt32)
        case wildcard
    }
    
    public var isWildcard: Bool {
        index == .wildcard
    }
    
    public init?(_ index: Index, isHardened: Bool = false) {
        if case let .childNum(i) = index {
            guard i < BIP32_INITIAL_HARDENED_CHILD else {
                return nil
            }
        }
        self.index = index
        self.isHardened = isHardened
    }
    
    public init?(_ index: UInt32, isHardened: Bool = false) {
        self.init(.childNum(index), isHardened: isHardened)
    }
    
    public init(rawValue: UInt32) {
        if rawValue < BIP32_INITIAL_HARDENED_CHILD {
            self.index = .childNum(rawValue)
            self.isHardened = false
        } else {
            self.index = .childNum(rawValue - BIP32_INITIAL_HARDENED_CHILD)
            self.isHardened = true
        }
    }
    
    public init?(string: String) {
        guard !string.isEmpty else {
            return nil
        }
        
        var s = string
        let isHardened: Bool
        if "'h".contains(s.last!) {
            isHardened = true
            s.removeLast()
        } else {
            isHardened = false
        }
        
        let index: Index
        if s == "*" {
            index = .wildcard
        } else if let v = UInt32(s) {
            index = .childNum(v)
        } else {
            return nil
        }
        
        self.init(index, isHardened: isHardened)
    }
    
    public func rawValue(wildcardChildNum: UInt32? = nil) -> UInt32? {
        let childNum: UInt32?
        if case let .childNum(num) = index {
            childNum = num
        } else {
            childNum = wildcardChildNum
        }
        guard let childNum = childNum else {
            return nil
        }
        if isHardened {
            return childNum + BIP32_INITIAL_HARDENED_CHILD
        } else {
            return childNum
        }
    }
}

extension DerivationStep: CustomStringConvertible {
    public var description: String {
        let value: String
        if case let .childNum(index) = index {
            value = String(index)
        } else {
            value = "*"
        }
        return value + (isHardened ? "h" : "")
    }
}

public struct DerivationPath : Equatable {
    public let origin: Origin?
    public let steps: [DerivationStep]
    
    public enum Origin: Equatable, CustomStringConvertible {
        case fingerprint(UInt32)
        case master
        
        public var description: String {
            switch self {
            case .fingerprint(let f):
                return f.hex
            case .master:
                return "m"
            }
        }
    }
    
    public init() {
        self.origin = nil
        self.steps = []
    }
    
    public init?(rawPath: [UInt32], origin: Origin? = nil) {
        let steps = rawPath.map { DerivationStep(rawValue: $0) }
        self.init(steps: steps, origin: origin)
    }
    
    public var isEmpty: Bool {
        steps.isEmpty && origin == nil
    }
    
    public var isHardened: Bool {
        steps.first(where: { $0.isHardened } ) != nil
    }
    
    public var hasWildcard: Bool {
        steps.contains(where: { $0.isWildcard })
    }
    
    public func rawPath(wildcardChildNum: UInt32? = nil) -> [UInt32?] {
        steps.map { $0.rawValue(wildcardChildNum: wildcardChildNum) }
    }
    
    public init(origin: Origin?) {
        self.steps = []
        self.origin = origin
    }
    
    public init(steps: [DerivationStep], origin: Origin? = nil) {
        self.steps = steps
        self.origin = origin
    }
    
    public init?(step: DerivationStep, origin: Origin? = nil) {
        self.init(steps: [step], origin: origin)
    }
    
    public init?(index: Int, origin: Origin? = nil) {
        guard let step = DerivationStep(UInt32(index)) else {
            return nil
        }
        self.init(steps: [step], origin: origin)
    }
    
    public init?(string: String) {
        var components = string.split(separator: "/")
        guard !components.isEmpty else {
            return nil
        }
        
        let origin: Origin?
        let o = String(components.first!)
        if o == "m" {
            origin = .master
            components.removeFirst()
        } else if let data = Data(hex: o), data.count == 4 {
            origin = .fingerprint(deserialize(UInt32.self, data)!)
            components.removeFirst()
        } else {
            origin = nil
        }
        
        var steps: [DerivationStep] = []
        components.forEach {
            guard let step = DerivationStep(string: String($0)) else {
                return
            }
            steps.append(step)
        }
        guard steps.count == components.count else {
            return nil
        }
        
        self.init(steps: steps, origin: origin)
    }
    
    public func chop(depth: Int) -> DerivationPath? {
        if depth > steps.count {
            return nil
        }
        var newSteps = self.steps
        newSteps.removeFirst(Int(depth))
        return DerivationPath(steps: newSteps, origin: nil)
    }
}

extension DerivationPath: CustomStringConvertible {
    public var description: String {
        var comps: [String] = []
        if let origin = origin {
            comps.append(origin.description)
        }
        for step in steps {
            comps.append(step.description)
        }
        return comps.joined(separator: "/")
    }
}

extension DerivationPath {
    static func getOrigins(keypaths: wally_map) -> [ECCompressedPublicKey: DerivationPath] {
        var result: [ECCompressedPublicKey: DerivationPath] = [:]
        for i in 0..<keypaths.num_items {
            // TOOD: simplify after https://github.com/ElementsProject/libwally-core/issues/241
            let item: wally_map_item = keypaths.items[i]

            let pubKey = ECCompressedPublicKey(Data(bytes: item.key, count: Int(EC_PUBLIC_KEY_LEN)))!
            let fingerprintData = Data(bytes: item.value, count: Int(BIP32_KEY_FINGERPRINT_LEN))
            let fingerprint = deserialize(UInt32.self, fingerprintData)!
            let keyPath = Data(bytes: item.value + Int(BIP32_KEY_FINGERPRINT_LEN), count: Int(item.value_len) - Int(BIP32_KEY_FINGERPRINT_LEN))

            var components: [UInt32] = []
            for j in 0..<keyPath.count / 4 {
                let data = keyPath.subdata(in: (j * 4)..<((j + 1) * 4)).withUnsafeBytes{ $0.load(as: UInt32.self) }
                components.append(data)
            }
            result[pubKey] = DerivationPath(rawPath: components, origin: .fingerprint(fingerprint))!
        }
        return result
    }
}

extension DerivationPath {
    public static func + (lhs: DerivationPath, rhs: DerivationPath) -> DerivationPath {
        DerivationPath(steps: lhs.steps + rhs.steps, origin: lhs.origin)
    }
}
