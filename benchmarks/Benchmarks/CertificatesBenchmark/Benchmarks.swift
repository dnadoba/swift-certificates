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

import Benchmark
import Foundation

let benchmarks = {
    Benchmark.defaultConfiguration = .init(
        metrics: [
//            .mallocCountTotal,
//            .syscalls,
//            .readSyscalls,
//            .writeSyscalls,
//            .memoryLeaked,
//            .retainCount,
//            .releaseCount,
            .wallClock,
        ]
    )
    
    var configWithoutRetainRelease = Benchmark.defaultConfiguration
    configWithoutRetainRelease.metrics.removeAll(where: { $0 == .retainCount || $0 == .releaseCount })
    
    Benchmark("Parse WebPKI from disk to CertificateStore") { _ in
        parseWebPKIFromDiskToCertificateStore()
    }
    
    Benchmark("Parse WebPKI Roots from multi PEM to PEMDocument ") { benchmark, run in
        for _ in 0..<100 {
            run()
        }
    } setup: {
        try! parseWebPKIFromMultiPEMStringToPEMDocument()
    }
    
    Benchmark("Parse WebPKI Roots from PEM to PEMDocument") { benchmark, run in
        for _ in 0..<100 {
            run()
        }
    } setup: {
        try! parseWebPKIFromPEMStringToPEMDocument()
    }

    Benchmark("Parse WebPKI Roots from PEM to Certificate") { benchmark, run in
        for _ in 0..<100 {
            run()
        }
    } setup: {
        try! parseWebPKIRootsFromPEM()
    }
    
    Benchmark("Parse WebPKI Roots from DER to Certificate") { benchmark, run in
        for _ in 0..<100 {
            run()
        }
    } setup: {
        try! parseWebPKIRootsFromDER()
    }
    
    Benchmark("Parse WebPKI Roots from PEM to PEMDocument concurrently") { benchmark, run in
        for _ in 0..<100 {
            run()
        }
    } setup: {
        try! parseWebPKIFromPEMStringToPEMDocumentConcurrent()
    }
    
    Benchmark("Parse WebPKI Roots from PEM to Certificate concurrently") { benchmark, run in
        for _ in 0..<100 {
            run()
        }
    } setup: {
        try! parseWebPKIRootsFromPEMConcurrent()
    }
    
    Benchmark("Parse WebPKI Roots from DER to Certificate concurrently") { benchmark, run in
        for _ in 0..<100 {
            run()
        }
    } setup: {
        try! parseWebPKIRootsFromDERConcurrent()
    }
    
    Benchmark("Verifier", configuration: configWithoutRetainRelease) { benchmark in
        for _ in benchmark.scaledIterations {
            await verifier()
        }
    }

    Benchmark("TinyArray non-allocating functions") { benchmark in
        for _ in benchmark.scaledIterations {
            tinyArrayNonAllocationFunctions()
        }
    }

    Benchmark("TinyArray.append(_:)") { benchmark in
        for _ in benchmark.scaledIterations {
            tinyArrayAppend()
        }
    }
}
