import Crypto
import Foundation

/// Narrow AWS Encryption SDK message format v2 profile, suite 0x0478
/// (AES-256-GCM, HKDF-SHA512, key commitment, no signature footer), one final frame.
/// Specification: aws-encryption-sdk-specification at f95ae385f2e5388d0c5e1dca9d7b592e7329dc2a.
/// The unsigned suite does not authenticate a sender against another DK holder; the outer
/// record signature, verified before any unwrap, is the sender-authentication barrier.
enum ESDK {
    static let messageVersion: UInt8 = 2
    static let suiteID: UInt16 = 0x0478
    static let contentTypeFramed: UInt8 = 2
    static let frameLength: UInt32 = 524_288
    static let finalFrameMarker: UInt32 = 0xffff_ffff
    static let providerID = Array("av-hpke-2".utf8)
    static let contextKey = Array("av-context".utf8)
    static let contextBytes = 80
    static let edkBytes = 128
    static let finalFrameAAD = Array("AWSKMSEncryptionClient Final Frame".utf8)
    static let hpkeSuite = HPKE.Ciphersuite.Curve25519_SHA256_ChachaPoly
    static let hpkeLabel = Array("AV/HPKE/2".utf8) + [0]
    static let finalFrameIV = [UInt8](repeating: 0, count: 11) + [1]

    struct EncryptedDataKey: Equatable {
        let role: UInt8
        let recipient: Data
        let encapsulation: Data
        let wrapped: Data

        var sortKey: [UInt8] { [role] + Array(recipient) }
    }

    struct Message {
        let messageID: Data
        let contextValue: Data
        let edks: [EncryptedDataKey]
        let commitment: Data
        /// `H`: header body from version through commitment, exactly as received.
        let header: Data
        let headerTag: Data
        let ciphertext: Data
        let frameTag: Data
    }

    // MARK: Key schedule (RFC 5869 HKDF-SHA512; AWS transitive requirements)

    struct DerivedKeys {
        let encryption: SymmetricKey
        let commitment: Data
    }

    static func derive(dataKey: SymmetricKey, messageID: Data) -> DerivedKeys {
        let prk = HKDF<SHA512>.extract(inputKeyMaterial: dataKey, salt: messageID)
        let suite = [UInt8(suiteID >> 8), UInt8(truncatingIfNeeded: suiteID)]
        let encryption = HKDF<SHA512>.expand(pseudoRandomKey: prk, info: suite + Array("DERIVEKEY".utf8),
                                             outputByteCount: 32)
        let commitment = HKDF<SHA512>.expand(pseudoRandomKey: prk, info: Array("COMMITKEY".utf8),
                                             outputByteCount: 32)
        return DerivedKeys(encryption: encryption, commitment: commitment.withUnsafeBytes { Data($0) })
    }

    // MARK: HPKE keyring binding (RFC 9180 base mode, 0x0020/0x0001/0x0003)

    static func hpkeInfo(headerHash: Data, messageID: Data) -> Data {
        Data(hpkeLabel) + headerHash + messageID
    }

    static func hpkeAAD(headerHash: Data, messageID: Data, commitment: Data, role: UInt8, recipient: Data) -> Data {
        headerHash + messageID + commitment + Data([role]) + recipient
    }

    /// One fresh sender context per recipient, used once for DK.
    static func wrap(_ dataKey: SymmetricKey, for recipient: Recipient, headerHash: Data, messageID: Data,
                     commitment: Data) throws(RecordError) -> EncryptedDataKey {
        do {
            let key = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: recipient.publicKey)
            var sender = try HPKE.Sender(recipientKey: key, ciphersuite: hpkeSuite,
                                         info: hpkeInfo(headerHash: headerHash, messageID: messageID))
            let wrapped = try dataKey.withUnsafeBytes {
                try sender.seal($0, authenticating: hpkeAAD(headerHash: headerHash, messageID: messageID,
                                                            commitment: commitment, role: recipient.role.rawValue,
                                                            recipient: recipient.publicKey))
            }
            return EncryptedDataKey(role: recipient.role.rawValue, recipient: recipient.publicKey,
                                    encapsulation: sender.encapsulatedKey, wrapped: wrapped)
        } catch {
            throw .invalidKey
        }
    }

    // MARK: Encoding

    static func context(headerHash: Data) -> [UInt8] {
        var writer = ByteWriter(capacity: contextBytes)
        writer.u16(1)
        writer.f16(contextKey)
        writer.f16(Array(hex(headerHash).utf8))
        return writer.bytes
    }

    static func header(messageID: Data, context: [UInt8], edks: [EncryptedDataKey], commitment: Data) -> Data {
        var writer = ByteWriter(capacity: 156 + edkBytes * edks.count)
        writer.u8(messageVersion)
        writer.u16(suiteID)
        writer.raw(messageID)
        writer.f16(context)
        writer.u16(UInt16(edks.count))
        for edk in edks {
            writer.f16(providerID)
            writer.f16([edk.role] + Array(edk.recipient))
            writer.f16(Array(edk.encapsulation + edk.wrapped))
        }
        writer.u8(contentTypeFramed)
        writer.u32(frameLength)
        writer.raw(commitment)
        return writer.data
    }

    /// AES-GCM over empty plaintext, nonce of twelve zero bytes, AAD exactly `H`.
    static func headerTag(key: SymmetricKey, header: Data) throws(RecordError) -> Data {
        do {
            let box = try AES.GCM.seal(Data(), using: key, nonce: AES.GCM.Nonce(data: Data(count: 12)),
                                       authenticating: header)
            return box.tag
        } catch {
            throw .invalidContent
        }
    }

    static func frameAAD(messageID: Data, contentLength: Int) -> Data {
        var writer = ByteWriter(capacity: 32 + finalFrameAAD.count + 12)
        writer.raw(messageID)
        writer.raw(finalFrameAAD)
        writer.u32(1)
        writer.u64(UInt64(contentLength))
        return writer.data
    }

    static func sealFrame(key: SymmetricKey, messageID: Data, padded: [UInt8]) throws(RecordError) -> (Data, Data) {
        do {
            let box = try AES.GCM.seal(padded, using: key, nonce: AES.GCM.Nonce(data: finalFrameIV),
                                       authenticating: frameAAD(messageID: messageID, contentLength: padded.count))
            return (box.ciphertext, box.tag)
        } catch {
            throw .invalidContent
        }
    }

    static func body(header: Data, headerTag: Data, ciphertext: Data, frameTag: Data) -> Data {
        var writer = ByteWriter(capacity: header.count + 56 + ciphertext.count)
        writer.raw(header)
        writer.raw(headerTag)
        writer.u32(finalFrameMarker)
        writer.u32(1)
        writer.raw(finalFrameIV)
        writer.u32(UInt32(ciphertext.count))
        writer.raw(ciphertext)
        writer.raw(frameTag)
        return writer.data
    }

    // MARK: Parsing (bounded and canonical; no key operation)

    static func parse(_ message: Data, maximumBucket: Int) throws(RecordError) -> Message {
        var reader = ByteReader(message)
        let start = reader.position
        guard try reader.u8() == messageVersion, try reader.u16() == suiteID else { throw .malformed }
        let messageID = try reader.take(32)
        guard try reader.u16() == contextBytes else { throw .malformed }
        var context = ByteReader(try reader.take(contextBytes))
        guard try context.u16() == 1, Array(try context.f16(maximum: contextKey.count)) == contextKey else {
            throw .malformed
        }
        let contextValue = try context.f16(maximum: 64)
        guard contextValue.count == 64,
              contextValue.allSatisfy({ (0x30...0x39).contains($0) || (0x61...0x66).contains($0) }) else {
            throw .malformed
        }
        try context.finish()
        let count = Int(try reader.u16())
        guard (1...RecipientSet.maximumCount).contains(count), count * edkBytes <= reader.remaining else {
            throw .malformed
        }
        var edks: [EncryptedDataKey] = []
        edks.reserveCapacity(count)
        for _ in 0..<count {
            guard Array(try reader.f16(maximum: providerID.count)) == providerID else { throw .malformed }
            var info = ByteReader(try reader.f16(maximum: 33))
            let role = try info.u8()
            guard RecipientRole(rawValue: role) != nil, info.remaining == 32 else { throw .malformed }
            let recipient = try info.take(32)
            var wrap = ByteReader(try reader.f16(maximum: 80))
            guard wrap.remaining == 80 else { throw .malformed }
            edks.append(EncryptedDataKey(role: role, recipient: recipient,
                                         encapsulation: try wrap.take(32), wrapped: try wrap.take(48)))
        }
        guard strictlyAscending(edks.map(\.sortKey)) else { throw .malformed }
        guard try reader.u8() == contentTypeFramed, try reader.u32() == frameLength else { throw .malformed }
        let commitment = try reader.take(32)
        let header = message[start..<reader.position]
        let headerTag = try reader.take(16)
        guard try reader.u32() == finalFrameMarker, try reader.u32() == 1,
              Array(try reader.take(12)) == finalFrameIV else { throw .malformed }
        let length = Int(try reader.u32())
        guard Payload.buckets.contains(length), length <= maximumBucket else { throw .malformed }
        let ciphertext = try reader.take(length)
        let frameTag = try reader.take(16)
        try reader.finish()
        return Message(messageID: messageID, contextValue: contextValue, edks: edks, commitment: commitment,
                       header: header, headerTag: headerTag, ciphertext: ciphertext, frameTag: frameTag)
    }

    // MARK: Opening (after signature, authority and every X25519 check)

    static func unwrap(_ edk: EncryptedDataKey, with key: RecipientKey, headerHash: Data,
                       message: Message) throws(RecordError) -> SymmetricKey {
        do {
            var recipient = try HPKE.Recipient(privateKey: key.privateKey, ciphersuite: hpkeSuite,
                                               info: hpkeInfo(headerHash: headerHash, messageID: message.messageID),
                                               encapsulatedKey: edk.encapsulation)
            var dataKey = try recipient.open(edk.wrapped, authenticating: hpkeAAD(
                headerHash: headerHash, messageID: message.messageID, commitment: message.commitment,
                role: edk.role, recipient: edk.recipient))
            defer { wipe(&dataKey) }
            guard dataKey.count == 32 else { throw RecordError.wrapAuthentication }
            return SymmetricKey(data: dataKey)
        } catch {
            throw .wrapAuthentication
        }
    }

    /// Commitment, then header tag, then frame. Returns padded plaintext; caller wipes it.
    static func decrypt(_ message: Message, dataKey: SymmetricKey) throws(RecordError) -> Data {
        let keys = derive(dataKey: dataKey, messageID: message.messageID)
        guard constantTimeEqual(keys.commitment, message.commitment) else { throw .commitmentMismatch }
        do {
            let box = try AES.GCM.SealedBox(nonce: AES.GCM.Nonce(data: Data(count: 12)), ciphertext: Data(),
                                            tag: message.headerTag)
            _ = try AES.GCM.open(box, using: keys.encryption, authenticating: message.header)
        } catch {
            throw .headerAuthentication
        }
        do {
            let box = try AES.GCM.SealedBox(nonce: AES.GCM.Nonce(data: finalFrameIV), ciphertext: message.ciphertext,
                                            tag: message.frameTag)
            return try AES.GCM.open(box, using: keys.encryption,
                                    authenticating: frameAAD(messageID: message.messageID,
                                                             contentLength: message.ciphertext.count))
        } catch {
            throw .frameAuthentication
        }
    }
}
