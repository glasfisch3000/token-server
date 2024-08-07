import Vapor
import NIOCore
import TokenServerAuth

extension TokenServer {
    private struct SetTokenRequestParameters: Decodable {
        enum CodingKeys: CodingKey {
            case domain
            case tokenID
            case pubKey
            case timestamp
            case signature
        }
        
        var domain: UUID
        var tokenID: String
        
        // signature verification data
        var pubKey: Curve25519.Signing.PublicKey
        var timestamp: Date
        var signature: Data
    }
    
    @Sendable
    public func setToken(_ request: Request) async throws -> Response {
        do {
            let params = try request.query.decode(SetTokenRequestParameters.self)
            
            var body = try await request.body.collect(upTo: 64)
            guard let tokenValue = body.readString(length: body.readableBytes, encoding: .utf8) else {
                throw Abort(.badRequest, reason: "unable to decode token value")
            }
            
            guard params.timestamp.timeIntervalSinceNow < 0 && params.timestamp.timeIntervalSinceNow > -self.configuration.signatureTimestampTolerance else {
                throw Abort(.forbidden, reason: "invalid timestamp")
            }
            
            guard let tokenStorage = self.tokens[params.domain] else {
                throw Abort(.notFound, reason: "unknown domain")
            }
            guard tokenStorage.authentication == params.pubKey else {
                throw Abort(.forbidden, reason: "invalid key")
            }
            
            guard try verify(params.signature, request: .setToken(domain: params.domain, tokenID: params.tokenID, token: tokenValue), date: params.timestamp, key: params.pubKey) else {
                throw Abort(.forbidden, reason: "invalid signature")
            }
            
            self.tokens[params.domain]?.tokens[params.tokenID] = tokenValue
            self.tokens[params.domain]?.revalidate(self.configuration.inactiveDomainTimeout)
            
            return Response(status: .ok, body: "stored")
        } catch let error as DecodingError {
            switch error {
            case .keyNotFound(let codingKey as SetTokenRequestParameters.CodingKeys, _):
                switch codingKey {
                case .domain: throw Abort(.badRequest, reason: "missing domain")
                case .tokenID: throw Abort(.badRequest, reason: "missing token id")
                case .pubKey, .timestamp, .signature: throw Abort(.unauthorized, reason: "missing signature")
                }
            default: throw Abort(.badRequest, reason: "invalid query")
            }
        } catch let error as SigningError {
            switch error {
            case .unableToEncodeUTF8: throw Abort(.internalServerError, reason: "unable to verify signature")
            }
        } catch _ as NIOTooManyBytesError {
            throw Abort(.payloadTooLarge, reason: "token content too large")
        }
    }
}
