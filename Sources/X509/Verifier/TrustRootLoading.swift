//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCertificates open source project
//
// Copyright (c) 2022 Apple Inc. and the SwiftCertificates project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftCertificates project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//


import Foundation
import SwiftASN1

struct TrustRootsLoadingError: Error {
    var errors: [(path: String, error: any Error)]
}

extension CertificateStore {
    @_spi(Testing)
    public static func loadTrustRoot(at searchPaths: [String]) throws -> CertificateStore {
        var fileLoadingError = TrustRootsLoadingError(errors: [])
        
        for path in searchPaths {
            let pemEncodedData: Data
            do {
                pemEncodedData = try Data(contentsOf: URL(fileURLWithPath: path))
            } catch {
                // this might fail if the file doesn't exists at which point we try the next path
                // but record the error if all fail
                fileLoadingError.errors.append((path, error))
                continue
            }
            
            return try parseTrustRoot(from: pemEncodedData)
        }
        
        throw fileLoadingError
    }
    
    static func parseTrustRoot(from pemEncodedData: Data) throws -> CertificateStore {
        let pemEncodedString = String(decoding: pemEncodedData, as: UTF8.self)
        let documents = try PEMDocument.parseMultiple(pemString: pemEncodedString)
        return CertificateStore(try documents.lazy.map {
            try Certificate(pemDocument: $0)
        })
    }
}

extension DispatchQueue {
    func asyncFuture<Success: Sendable>(withResultOf work: @Sendable @escaping () throws -> Success) -> Future<Success, any Error> {
        let promise = Promise<Success, any Error>()
        self.async {
            promise.fulfil(with: Result { try work() })
        }
        return Future(promise)
    }
}

#if os(Linux)
/// This is a list of root CA file search paths. This list contains paths as validated against several distributions.
/// If you are attempting to use swift-certificates on a platform that is not covered here and certificate validation is
/// failing, please open a pull request that adds the appropriate search path.
private let rootCAFileSearchPaths = [
    "/etc/ssl/certs/ca-certificates.crt",  // Ubuntu, Debian, Arch, Alpine,
    "/etc/pki/tls/certs/ca-bundle.crt",  // Fedora
]

extension CertificateStore {
    static let cachedSystemTrustRootsFuture: Future<CertificateStore, any Error> = DispatchQueue.global(qos: .userInteractive).asyncFuture {
        try Self.loadTrustRoot(at: rootCAFileSearchPaths)
    }
    
    public static let systemTrustRoots: CertificateStore = {
        // access `cachedTrustRootsFuture` to kick off loading on a background thread
        _ = cachedSystemTrustRootsFuture
        return CertificateStore(elements: CollectionOfOne(.trustRoots))
    }()
}
#endif
