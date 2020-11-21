//
//  LibWallyError.swift
//  LibWally
//
//  Created by Wolf McNally on 11/20/20.
//

import Foundation

public struct LibWallyError: LocalizedError {
    public let description: String

    public init(_ description: String) {
        self.description = description
    }
    
    public var errorDescription: String? {
        return description
    }
}
