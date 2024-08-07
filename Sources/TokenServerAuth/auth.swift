import Foundation
import Crypto

public enum SignableRequest: Hashable {
    case getDomain(domain: UUID)
    case deleteDomain(domain: UUID)
    case getToken(domain: UUID, tokenID: String)
    case setToken(domain: UUID, tokenID: String, token: String)
    case deleteToken(domain: UUID, tokenID: String)
}

public enum SigningError: Error {
    case unableToEncodeUTF8
}

public func createSignableData(request: SignableRequest, date: Date) throws -> Data {
    let strings: [String] = switch request {
    case .getDomain(let domain): ["getDomain", domain.uuidString]
    case .deleteDomain(let domain): ["deleteDomain", domain.uuidString]
    case .getToken(let domain, let tokenID): ["getToken", domain.uuidString, tokenID]
    case .setToken(let domain, let tokenID, let token): ["setToken", domain.uuidString, tokenID, token]
    case .deleteToken(let domain, let tokenID): ["deleteToken", domain.uuidString, tokenID]
    }
    
    guard var data = strings.joined(separator: "").data(using: .utf8) else {
        throw SigningError.unableToEncodeUTF8
    }
    
    var date = date.timeIntervalSince1970
    data.append(contentsOf: withUnsafeBytes(of: &date) { Array($0) })
    
    return data
}

public func sign(request: SignableRequest, date: Date, key: Curve25519.Signing.PrivateKey) throws -> Data {
    let data = try createSignableData(request: request, date: date)
    return try key.signature(for: data)
}

public func verify(_ signature: Data, request: SignableRequest, date: Date, key: Curve25519.Signing.PublicKey) throws -> Bool {
    let data = try createSignableData(request: request, date: date)
    return key.isValidSignature(signature, for: data)
}
