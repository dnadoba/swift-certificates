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

final class Promise<Value, Failure: Error> {
    private enum State {
        case unfulfilled(observers: [CheckedContinuation<Result<Value, Failure>, Never>])
        case fulfilled(Result<Value, Failure>)
    }
    
    private let state = LockedValueBox(State.unfulfilled(observers: []))
    
    init() {}
    
    fileprivate var result: Result<Value, Failure> {
        get async {
            self.state.lock()
            
            switch self.state.unlockedValue {
            case .fulfilled(let result):
                defer { self.state.unlock() }
                return result
            
            case .unfulfilled(var observers):
                return await withCheckedContinuation { (continuation: CheckedContinuation<Result<Value, Failure>, Never>) in
                    observers.append(continuation)
                    self.state.unlockedValue = .unfulfilled(observers: observers)
                    self.state.unlock()
                }
            }
        }
    }
    
    func fulfil(with result: Result<Value, Failure>) {
        self.state.withLockedValue { state in
            switch state {
            case .fulfilled(let oldResult):
                fatalError("tried to fulfil Promise that is already fulfilled to \(oldResult). New result: \(result)")
            case .unfulfilled(let observers):
                for observer in observers {
                    observer.resume(returning: result)
                }
                state = .fulfilled(result)
            }
        }
    }
}

extension Promise {
    func succeed(with value: Value) {
        self.fulfil(with: .success(value))
    }
    
    func fail(with error: Failure) {
        self.fulfil(with: .failure(error))
    }
}

extension Promise: Sendable where Value: Sendable {}


struct Future<Value, Failure: Error> {
    private let promise: Promise<Value, Failure>
    
    var result: Result<Value, Failure> {
        get async {
            await promise.result
        }
    }
}

extension Future: Sendable where Value: Sendable {}

extension Future {
    var value: Value {
        get async throws {
            try await result.get()
        }
    }
}

extension Future where Failure == Never {
    var value: Value {
        get async {
            await result.get()
        }
    }
}

extension Result where Failure == Never {
    func get() -> Success {
        switch self {
        case .success(let success):
            return success
        }
    }
}
