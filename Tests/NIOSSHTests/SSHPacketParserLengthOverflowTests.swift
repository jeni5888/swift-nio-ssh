//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2019 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import Crypto
import NIOCore
@testable import NIOSSH
import XCTest

/// Regression coverage for the unchecked addition in `SSHPacketParser.decryptLength`:
///
///     let packetLength = self.buffer.getInteger(at: self.buffer.readerIndex, as: UInt32.self)!
///     let decryptedLength = packetLength + UInt32(protection.macBytes)
///
/// An attacker controls `packetLength` (the length field is unauthenticated plaintext), so a
/// length within `macBytes` of `UInt32.max` makes that addition overflow before any bound is
/// consulted. The length must be bounded *before* the add.
final class SSHPacketParserLengthOverflowTests: XCTestCase {
    /// Feeds the SSH version string so the parser reaches `.cleartextWaitingForLength` — the only
    /// state from which `SSHPacketParser.addEncryption(_:)` is permitted. (Cited by symbol, not by
    /// line: the fix this file covers inserted lines above it.)
    private func feedVersion(to parser: inout SSHPacketParser, file: StaticString = #filePath, line: UInt = #line) {
        var version = ByteBuffer.of(string: "SSH-2.0-OpenSSH_7.9\r\n")
        parser.append(bytes: &version)

        var packet: SSHMessage?
        XCTAssertNoThrow(packet = try parser.nextPacket(), file: file, line: line)

        switch packet {
        case .some(.version(let string)):
            XCTAssertEqual(string, "SSH-2.0-OpenSSH_7.9", file: file, line: line)
        default:
            XCTFail("Expecting .version", file: file, line: line)
        }
    }

    /// AES-128-GCM in OpenSSH mode is the transport protection this test needs: its
    /// `decryptFirstBlock` is an empty body — "For us, decrypting the first block is very easy: do
    /// nothing. The length bytes are already unencrypted!" (`AESGCM.swift:82-85`) — so the four
    /// length bytes written below reach `decryptLength` byte-for-byte, and it cannot throw and mask
    /// the parser's own error. `cipherBlockSize` is 16 (`AESGCM.swift:61-63`) and `macBytes` is 16
    /// (`AESGCM.swift:65-67`).
    ///
    /// The IVs must be exactly 12 bytes: `SSHAESGCMNonce.init(keyExchangeResult:)` throws
    /// `NIOSSHError.invalidNonceLength` otherwise (`AESGCM.swift:257-260`).
    private func makeProtection() throws -> AES128GCMOpenSSHTransportProtection {
        let keys = NIOSSHSessionKeys(
            initialInboundIV: [UInt8](repeating: 0, count: 12),
            initialOutboundIV: [UInt8](repeating: 0, count: 12),
            inboundEncryptionKey: SymmetricKey(size: .bits128),
            outboundEncryptionKey: SymmetricKey(size: .bits128),
            inboundMACKey: SymmetricKey(size: .bits128),
            outboundMACKey: SymmetricKey(size: .bits128)
        )
        return try AES128GCMOpenSSHTransportProtection(initialKeys: keys, mac: nil)
    }

    func testEncryptedLengthNearUInt32MaxIsRejectedRatherThanOverflowing() throws {
        var parser = SSHPacketParser(allocator: ByteBufferAllocator())
        self.feedVersion(to: &parser)

        let protection = try self.makeProtection()
        parser.addEncryption(protection)

        // Exactly one cipher block, so `decryptLength`'s `readableBytes >= blockSize` guard passes
        // and nothing is allocated for a body:
        //
        //   length field = 0xFF 0xFF 0xFF 0xFF = UInt32.max = 4_294_967_295
        //   macBytes     = 16
        //   4_294_967_295 + 16 = 4_294_967_311 > UInt32.max  -> overflow
        //
        // Unfixed: that `+` traps (SIGTRAP/SIGILL), killing the test process.
        // Fixed:   the guard inserted before the add sees 0xFFFFFFFF >= maximumPacketSize
        //          (1 << 17 = 131_072 by default) and throws `.invalidEncryptedPacketLength`.
        var firstBlock = ByteBuffer.of(bytes: [0xFF, 0xFF, 0xFF, 0xFF] + [UInt8](repeating: 0, count: 12))
        XCTAssertEqual(firstBlock.readableBytes, protection.cipherBlockSize)
        parser.append(bytes: &firstBlock)

        XCTAssertThrowsError(try parser.nextPacket()) { error in
            // Same error as the surviving post-add check (`decryptedLength >= maximumPacketSize`),
            // which the fix deliberately leaves in place.
            XCTAssertEqual((error as? NIOSSHError)?.type, .invalidEncryptedPacketLength)
        }
    }
}
