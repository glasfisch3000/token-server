import Foundation
import Crypto

public struct TokenStorage: Hashable, Codable, Sendable {
    public var domain: UUID
    public var authentication: Curve25519.Signing.PublicKey
    public var tokens: [String: String]
    public var expires: Date
    
    @discardableResult
    mutating func revalidate(_ timeout: TimeInterval) -> Date {
        self.expires.addTimeInterval(timeout)
        return self.expires
    }
}

extension Curve25519.Signing.PublicKey: Hashable {
    public static func == (lhs: Curve25519.Signing.PublicKey, rhs: Curve25519.Signing.PublicKey) -> Bool {
        lhs.rawRepresentation == rhs.rawRepresentation
    }
    
    public func hash(into hasher: inout Hasher) {
        hasher.combine(self.rawRepresentation)
    }
}

extension Curve25519.Signing.PublicKey: Codable {
    public init(from decoder: any Decoder) throws {
        try self.init(rawRepresentation: try Data(from: decoder))
    }
    
    public func encode(to encoder: any Encoder) throws {
        try self.rawRepresentation.encode(to: encoder)
    }
}
