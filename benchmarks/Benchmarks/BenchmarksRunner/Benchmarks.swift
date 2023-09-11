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
import Benchmarks
import Foundation

let benchmarks = {
    Benchmark.defaultConfiguration = .init(
        metrics: [.mallocCountTotal, .syscalls] + .arc,
        warmupIterations: 1
    )
    
    let runParseWebPKIFromMultiPEMStringToPEMDocument = try! parseWebPKIFromMultiPEMStringToPEMDocument()
    Benchmark("Parse WebPKI Roots from multi PEM to PEMDocument ", configuration: .init(metrics: [.mallocCountTotal, .throughput, .wallClock])) { benchmark in
        for _ in 0..<100 {
            runParseWebPKIFromMultiPEMStringToPEMDocument()
        }
    }
    
    let runParseWebPKIFromPEMStringToPEMDocument = try! parseWebPKIFromPEMStringToPEMDocument()
    Benchmark("Parse WebPKI Roots from PEM to PEMDocument ", configuration: .init(metrics: [.mallocCountTotal, .throughput, .wallClock])) { benchmark in
        for _ in 0..<100 {
            runParseWebPKIFromPEMStringToPEMDocument()
        }
    }

    let runParseWebPKIRootsFromPEM = try! parseWebPKIRootsFromPEM()
    Benchmark("Parse WebPKI Roots from PEM to Certificate", configuration: .init(metrics: [.mallocCountTotal, .throughput, .wallClock])) { benchmark in
        for _ in 0..<100 {
            runParseWebPKIRootsFromPEM()
        }
    }
    
    let runParseWebPKIRootsFromDER = try! parseWebPKIRootsFromDER()
    Benchmark("Parse WebPKI Roots from DER to Certificate", configuration: .init(metrics: [.mallocCountTotal, .throughput, .wallClock])) { benchmark in
        for _ in 0..<100 {
            runParseWebPKIRootsFromDER()
        }
    }
    
    let runParseWebPKIFromPEMStringToPEMDocumentConcurrent = try! parseWebPKIFromPEMStringToPEMDocumentConcurrent()
    Benchmark("Parse WebPKI Roots from PEM to PEMDocument concurrently", configuration: .init(metrics: [.mallocCountTotal, .throughput, .wallClock])) { benchmark in
        for _ in 0..<100 {
            runParseWebPKIFromPEMStringToPEMDocumentConcurrent()
        }
    }
    
    let runParseWebPKIRootsFromPEMConcurrent = try! parseWebPKIRootsFromPEMConcurrent()
    Benchmark("Parse WebPKI Roots from PEM to Certificate concurrently", configuration: .init(metrics: [.mallocCountTotal, .throughput, .wallClock])) { benchmark in
        for _ in 0..<100 {
            runParseWebPKIRootsFromPEMConcurrent()
        }
    }
    
    let runParseWebPKIRootsFromDERConcurrent = try! parseWebPKIRootsFromDERConcurrent()
    Benchmark("Parse WebPKI Roots from DER to Certificate concurrently", configuration: .init(metrics: [.mallocCountTotal, .throughput, .wallClock])) { benchmark in
        for _ in 0..<100 {
            runParseWebPKIRootsFromDERConcurrent()
        }
    }
    
    Benchmark("Verifier", configuration: .init(metrics: [.mallocCountTotal, .syscalls])) { benchmark in
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
