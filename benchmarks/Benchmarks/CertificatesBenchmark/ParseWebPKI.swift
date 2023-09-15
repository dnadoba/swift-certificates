//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCertificates open source project
//
// Copyright (c) 2023 Apple Inc. and the SwiftCertificates project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftCertificates project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import BlackHole
import X509
import SwiftASN1
import Foundation

public func parseWebPKIFromMultiPEMStringToPEMDocument() throws -> () -> Void {
    let caPEMs = try loadWebPKIAsSingleMuliPEMString()
    return {
        blackHole(try! PEMDocument.parseMultiple(pemString: caPEMs))
    }
}

//public func parseWebPKIFromMultiPEMStringToPEMDocument() throws -> () -> Void {
//    let caPEMs = try loadWebPKIAsSingleMuliPEMString()
//    return {
//        blackHole(try! PEMDocument.multipleConcurrent(pemString: caPEMs, transform: { _ in }))
//    }
//}

//public func parseWebPKIFromMultiPEMStringToCertificate() throws -> () -> Void {
//    let caPEMs = try loadWebPKIAsSingleMuliPEMString()
//    return {
//        blackHole(try! PEMDocument.multipleConcurrent(pemString: caPEMs, transform: {
//            Certificate.init
//        }))
//    }
//}

public func parseWebPKIFromPEMStringToPEMDocument() throws -> () -> Void {
    let caPEMs = try loadWebPKIAsPemStrings()
    return {
        blackHole(caPEMs.map { pemString in
            try! PEMDocument(pemString: pemString)
        })
    }
}

public func parseWebPKIFromPEMStringToPEMDocumentConcurrent() throws -> () -> Void {
    let caPEMs = try loadWebPKIAsPemStrings()
    return {
        blackHole(caPEMs.concurrentMap { pemString in
            try! PEMDocument(pemString: pemString)
        })
    }
}

public func parseWebPKIRootsFromPEM() throws -> () -> Void {
    let pemEncodedCAs = try loadWebPKIAsPemStrings()
    return {
        for pemEncodedCA in pemEncodedCAs {
            let derEncodedCA = try! PEMDocument(pemString: pemEncodedCA).derBytes
            blackHole(try! Certificate(derEncoded: derEncodedCA).extensions.count)
        }
    }
}

public func parseWebPKIRootsFromPEMConcurrent() throws -> () -> Void {
    let pemEncodedCAs = try loadWebPKIAsPemStrings()
    return {
        blackHole(pemEncodedCAs.concurrentMap { pemEncodedCA in
            let derEncodedCA = try! PEMDocument(pemString: pemEncodedCA).derBytes
            return try! Certificate(derEncoded: derEncodedCA)
        })
    }
}

public func parseWebPKIRootsFromDER() throws -> () -> Void {
    let derEncodedCAs = try loadWebPKIAsPemStrings().map { try! PEMDocument(pemString: $0).derBytes }
    return {
        for derEncodedCA in derEncodedCAs {
            blackHole(try! Certificate(derEncoded: derEncodedCA).extensions.count)
        }
    }
}

public func parseWebPKIRootsFromDERConcurrent() throws -> () -> Void {
    let derEncodedCAs = try loadWebPKIAsPemStrings().map { try! PEMDocument(pemString: $0).derBytes }
    return {
        blackHole(derEncodedCAs.concurrentMap { derEncodedCA in
            try! Certificate(derEncoded: derEncodedCA)
        })
    }
}

extension Array where Element: Sendable {
    func concurrentMap<TransformedElement: Sendable>(
        _ transform: @Sendable (Element) throws -> TransformedElement
    ) -> [Result<TransformedElement, any Error>] {
        Array<Result<TransformedElement, any Error>>.init(unsafeUninitializedCapacity: self.count) { resultBuffer, initializedCount in
            DispatchQueue.concurrentPerform(iterations: self.count) { index in
                let element = self[index]
                let result = Result { try transform(element) }
                resultBuffer.initializeElement(at: index, to: result)
            }
            initializedCount = self.count
        }
    }
}
