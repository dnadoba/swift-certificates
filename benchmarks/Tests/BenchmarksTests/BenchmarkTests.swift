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

import Benchmarks
import BlackHole
import XCTest

final class TestRunner: XCTestCase {
//    override func setUp() {
//        #if DEBUG
//        fatalError("performance tests only run in release mode")
//        #endif
//    }
    
    func testParseWebPKIFromMultiPEMStringToPEMDocument() throws {
        let run = try parseWebPKIFromMultiPEMStringToPEMDocument()
        for _ in 0..<100 {
            run()
        }
    }
    
    func testParseWebPKIFromPEMStringToPEMDocument() throws {
        let run = try parseWebPKIFromPEMStringToPEMDocument()
        for _ in 0..<100 {
            run()
        }
    }
    
    func testParseWebPKIRootsFromPEM() throws {
        let run = try parseWebPKIRootsFromPEM()
        for _ in 0..<100 {
            run()
        }
    }
    
    func testParseWebPKIRootsFromDER() throws {
        let run = try parseWebPKIRootsFromDER()
        for _ in 0..<100 {
            run()
        }
    }
    
    func testParseWebPKIFromPEMStringToPEMDocumentConcurrent() throws {
        let run = try parseWebPKIFromPEMStringToPEMDocumentConcurrent()
        for _ in 0..<100 {
            run()
        }
    }
    
    func testParseWebPKIRootsFromPEMConcurrent() throws {
        let run = try parseWebPKIRootsFromPEMConcurrent()
        for _ in 0..<100 {
            run()
        }
    }
    
    func testParseWebPKIRootsFromDERConcurrent() throws {
        let run = try parseWebPKIRootsFromDERConcurrent()
        for _ in 0..<100 {
            run()
        }
    }
    
    func testVerifier() async {
        for _ in 0..<100 {
            await verifier()
        }
    }

    func testTinyArrayNonAllocationFunctions() {
        for _ in 0..<1000 {
            tinyArrayNonAllocationFunctions()
        }
    }

    func testTinyArrayAppend() {
        for _ in 0..<1000 {
            tinyArrayAppend()
        }
    }
}
