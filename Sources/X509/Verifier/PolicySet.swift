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

import SwiftASN1

@available(macOS 14.0.0, *)
public struct PolicySet<each Policy: VerifierPolicy> {
    @usableFromInline
    var policy: (repeat each Policy)
    
    @usableFromInline
    var verifyingCriticalExtensions: [ASN1ObjectIdentifier]
    
    @inlinable
    init(policy: (repeat each Policy)) {
        self.policy = policy

        var extensions: [ASN1ObjectIdentifier] = []
        var totalExtensionCount = 0
        repeat totalExtensionCount += (each policy).verifyingCriticalExtensions.count
        extensions.reserveCapacity(totalExtensionCount)

        repeat extensions.append(contentsOf: (each policy).verifyingCriticalExtensions)
        
        self.verifyingCriticalExtensions = extensions
    }
    
    @inlinable
    mutating func chainMeetsPolicyRequirements(chain: UnverifiedCertificateChain) async -> PolicyEvaluationResult {
        do {
            repeat try await (each policy).chainMeetsPolicyRequirementsOrThrow(chain: chain)
            return .meetsPolicy
        } catch {
            return .failsToMeetPolicy(reason: (error as! VerifierError).reason)
        }
    }
}

protocol BarProtocol {
    mutating func mutate()
}

@available(macOS 14.0.0, *)
struct Foo<each Bar: BarProtocol> {
    var bar: (repeat each Bar)
    
    mutating func mutate() {
        repeat (each bar).mutate()
    }
}

@usableFromInline
struct VerifierError: Error {
    @usableFromInline
    var reason: String
    
    @inlinable
    init(reason: String) {
        self.reason = reason
    }
}

extension VerifierPolicy {
    @inlinable
    mutating func chainMeetsPolicyRequirementsOrThrow(chain: UnverifiedCertificateChain) async throws {
        switch await self.chainMeetsPolicyRequirements(chain: chain) {
        case .meetsPolicy:
            ()
        case .failsToMeetPolicy(reason: let reason):
            throw VerifierError(reason: reason)
        }
    }
}
