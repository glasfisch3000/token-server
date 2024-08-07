import Vapor
import TokenServerAuth

extension TokenServer {
    private struct GetDomainRequestParameters: Decodable {
        enum CodingKeys: CodingKey {
            case domain
            case pubKey
            case timestamp
            case signature
        }
        
        var domain: UUID
        
        // signature verification data
        var pubKey: Curve25519.Signing.PublicKey
        var timestamp: Date
        var signature: Data
    }
    
    @Sendable
    public func getDomain(_ request: Request) async throws -> Response {
        do {
            let params = try request.query.decode(GetDomainRequestParameters.self)
            let domain = params.domain
            let key = params.pubKey
            let date = params.timestamp
            let signature = params.signature
            
            guard date.timeIntervalSinceNow < 0 && date.timeIntervalSinceNow > -self.configuration.signatureTimestampTolerance else {
                throw Abort(.forbidden, reason: "invalid timestamp")
            }
            
            guard let tokenStorage = self.tokens[domain] else {
                throw Abort(.notFound, reason: "unknown domain")
            }
            guard tokenStorage.authentication == key else {
                throw Abort(.forbidden, reason: "invalid key")
            }
            
            guard try verify(params.signature, request: .getDomain(domain: params.domain), date: date, key: params.pubKey) else {
                throw Abort(.forbidden, reason: "invalid signature")
            }
            
            self.tokens[domain]?.revalidate(self.configuration.inactiveDomainTimeout)
            
            let responseData = try JSONEncoder().encode(tokenStorage.tokens)
            return Response(status: .ok, body: .init(data: responseData))
        } catch let error as DecodingError {
            switch error {
            case .keyNotFound(let codingKey as GetDomainRequestParameters.CodingKeys, _):
                switch codingKey {
                case .domain: throw Abort(.badRequest, reason: "missing domain")
                case .pubKey, .timestamp, .signature: throw Abort(.unauthorized, reason: "missing signature")
                }
            default: throw Abort(.badRequest, reason: "invalid query")
            }
        } catch let error as SigningError {
            switch error {
            case .unableToEncodeUTF8: throw Abort(.internalServerError, reason: "unable to verify signature")
            }
        } catch let error as EncodingError {
            throw Abort(.internalServerError, reason: "unable to encode data")
        }
    }
}