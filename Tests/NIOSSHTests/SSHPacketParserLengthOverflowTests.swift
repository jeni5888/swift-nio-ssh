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

    /// The whole trapping WINDOW, not just its last value.
    ///
    /// The test above feeds exactly `UInt32.max`, and that is too narrow to pin the property: a
    /// guard written `packetLength != UInt32.max` would pass it while leaving the trap alive for
    /// every length in `UInt32.max - macBytes ... UInt32.max - 1` (measured: that wrong guard keeps
    /// the test above green). Any length in that window overflows `packetLength + macBytes`, so
    /// each one must come back as a protocol error instead of killing the process.
    func testEveryLengthInTheOverflowWindowIsRejected() throws {
        let protection = try self.makeProtection()
        // macBytes = 16, so the window is the last 16 representable lengths. Take its two ends and
        // one value in between; the first is also the one a `!= UInt32.max` guard would let through.
        for length in [UInt32.max - 1, UInt32.max - UInt32(protection.macBytes) + 1, UInt32.max] {
            var parser = SSHPacketParser(allocator: ByteBufferAllocator())
            self.feedVersion(to: &parser)
            parser.addEncryption(protection)
            var block = ByteBuffer.of(bytes: self.lengthBlock(length, blockSize: protection.cipherBlockSize))
            parser.append(bytes: &block)
            XCTAssertThrowsError(try parser.nextPacket(), "length \(length) must be rejected") { error in
                XCTAssertEqual((error as? NIOSSHError)?.type, .invalidEncryptedPacketLength)
            }
        }
    }

    /// The bound itself, from both sides.
    ///
    /// The overflow test above pins ONE value (`UInt32.max`). This one pins the BOUNDARY, which is
    /// the property the pre-add guard was added under: that the set of accepted lengths is
    /// unchanged. `maximumPacketSize - macBytes - 1` is the largest length the parser accepted
    /// before the guard existed and must still be accepted; `maximumPacketSize` must be rejected.
    ///
    /// What this test deliberately does NOT claim, because it was measured: it does not catch an
    /// off-by-one IN the pre-add guard. Turning its `<` into `<=` leaves this test green — and
    /// nothing could catch it, because such a change has no observable effect at all. The
    /// surviving post-add check rejects everything from `maximumPacketSize - macBytes` upwards, so
    /// it already covers every value the pre-add guard's comparison could disagree about. The
    /// guard's unique duty is the arithmetic trap near `UInt32.max`, and the test above pins that.
    func testTheLengthBoundIsCheckedFromBothSides() throws {
        let protection = try self.makeProtection()
        let maximumPacketSize = SSHPacketParser.defaultMaximumPacketSize

        // Just inside: accepted by the length check, so `decryptLength` must not throw. The parser
        // then waits for the rest of the packet, i.e. `nextPacket()` returns nil rather than
        // erroring — which is exactly what "this length was accepted" looks like from outside.
        var parser = SSHPacketParser(allocator: ByteBufferAllocator())
        self.feedVersion(to: &parser)
        parser.addEncryption(protection)
        let accepted = UInt32(maximumPacketSize - protection.macBytes - 1)
        var insideBlock = ByteBuffer.of(bytes: self.lengthBlock(accepted, blockSize: protection.cipherBlockSize))
        parser.append(bytes: &insideBlock)
        XCTAssertNoThrow(XCTAssertNil(try parser.nextPacket()))

        // On the bound: rejected. `maximumPacketSize` + macBytes is >= maximumPacketSize, which the
        // surviving post-add check rejects, and the pre-add guard rejects it too.
        var parser2 = SSHPacketParser(allocator: ByteBufferAllocator())
        self.feedVersion(to: &parser2)
        parser2.addEncryption(protection)
        var onBoundBlock = ByteBuffer.of(
            bytes: self.lengthBlock(UInt32(maximumPacketSize), blockSize: protection.cipherBlockSize)
        )
        parser2.append(bytes: &onBoundBlock)
        XCTAssertThrowsError(try parser2.nextPacket()) { error in
            XCTAssertEqual((error as? NIOSSHError)?.type, .invalidEncryptedPacketLength)
        }
    }

    /// One cipher block whose first four bytes are `length` big-endian, zero-padded.
    private func lengthBlock(_ length: UInt32, blockSize: Int) -> [UInt8] {
        let be = [
            UInt8(truncatingIfNeeded: length >> 24), UInt8(truncatingIfNeeded: length >> 16),
            UInt8(truncatingIfNeeded: length >> 8), UInt8(truncatingIfNeeded: length),
        ]
        return be + [UInt8](repeating: 0, count: blockSize - be.count)
    }
}
