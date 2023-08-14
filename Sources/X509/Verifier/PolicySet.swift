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

@available(macOS 14, iOS 17, tvOS 17, watchOS 10, *)
public struct PolicySet<each Policy: VerifierPolicy>: VerifierPolicy {
    @usableFromInline
    var policy: (repeat each Policy)
    
    @usableFromInline
    var _verifyingCriticalExtensions: [ASN1ObjectIdentifier]
    
    @inlinable
    public var verifyingCriticalExtensions: [ASN1ObjectIdentifier] {
        _verifyingCriticalExtensions
    }
    
    @inlinable
    public init(_ policy: (repeat each Policy)) {
        self.policy = policy

        var extensions: [ASN1ObjectIdentifier] = []
        var totalExtensionCount = 0
        repeat totalExtensionCount += (each policy).verifyingCriticalExtensions.count
        extensions.reserveCapacity(totalExtensionCount)

        repeat extensions.append(contentsOf: (each policy).verifyingCriticalExtensions)
        
        self._verifyingCriticalExtensions = extensions
    }
    
    @inlinable
    public mutating func chainMeetsPolicyRequirements(chain: UnverifiedCertificateChain) async -> PolicyEvaluationResult {
        // variadic generic currently cannot call mutating methods.
        // This is a workaround according to https://forums.swift.org/t/is-there-a-way-to-implement-zipsequence-iterator-s-next-method-from-se-0398/66680/2
        func chainMeetsPolicyRequirementsOrThrow<SpecificPolicy: VerifierPolicy>(
            policy: SpecificPolicy
        ) async throws -> SpecificPolicy {
            var policy = policy
            try await policy.chainMeetsPolicyRequirementsOrThrow(chain: chain)
            return policy
        }
        
        do {
            var policy: (repeat each Policy) = self.policy
            policy = try await (repeat chainMeetsPolicyRequirementsOrThrow(policy: each policy))
            self.policy = policy
            return .meetsPolicy
        } catch {
            return .failsToMeetPolicy(reason: (error as! VerifierError).reason)
        }
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
