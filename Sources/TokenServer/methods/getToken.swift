import Vapor
import TokenServerAuth

extension TokenServer {
    private struct GetTokenRequestParameters: Decodable {
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
    public func getToken(_ request: Request) async throws -> Response {
        do {
            let params = try request.query.decode(GetTokenRequestParameters.self)
            
            guard params.timestamp.timeIntervalSinceNow < 0 && params.timestamp.timeIntervalSinceNow > -self.configuration.signatureTimestampTolerance else {
                throw Abort(.forbidden, reason: "invalid timestamp")
            }
            
            guard let tokenStorage = self.tokens[params.domain] else {
                throw Abort(.notFound, reason: "unknown domain")
            }
            guard tokenStorage.authentication == params.pubKey else {
                throw Abort(.forbidden, reason: "invalid key")
            }
            
            guard try verify(params.signature, request: .getToken(domain: params.domain, tokenID: params.tokenID), date: params.timestamp, key: params.pubKey) else {
                throw Abort(.forbidden, reason: "invalid signature")
            }
            
            guard let token = tokenStorage.tokens[params.tokenID] else {
                throw Abort(.notFound, reason: "unknown token")
            }
            
            self.tokens[params.domain]?.revalidate(self.configuration.inactiveDomainTimeout)
            
            let responseData = try JSONEncoder().encode(token)
            return Response(status: .ok, body: .init(data: responseData))
        } catch let error as DecodingError {
            switch error {
            case .keyNotFound(let codingKey as GetTokenRequestParameters.CodingKeys, _):
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
        } catch _ as EncodingError {
            throw Abort(.internalServerError, reason: "unable to encode data")
        }
    }
}
