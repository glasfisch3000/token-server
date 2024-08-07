import Vapor
import TokenServerAuth

extension TokenServer {
    private struct CreateDomainRequestParameters: Decodable {
        enum CodingKeys: CodingKey {
            case pubKey
        }
        
        var pubKey: Curve25519.Signing.PublicKey
    }
    
    private struct CreateDomainRequestResponse: Encodable {
        var domain: UUID
        var expires: Date
    }
    
    @Sendable
    public func createDomain(_ request: Request) async throws -> Response {
        do {
            let params = try request.query.decode(CreateDomainRequestParameters.self)
            let key = params.pubKey
            
            let uuid = UUID()
            let expires = Date.now.addingTimeInterval(self.configuration.inactiveDomainTimeout)
            self.tokens[uuid] = .init(domain: uuid,
                                      authentication: key,
                                      tokens: [:],
                                      expires: expires)
            
            let response = CreateDomainRequestResponse(domain: uuid, expires: expires)
            let encodedData = try JSONEncoder().encode(response)
            return Response(status: .ok, body: .init(data: encodedData))
        } catch let error as DecodingError {
            switch error {
            case .keyNotFound(let codingKey as CreateDomainRequestParameters.CodingKeys, _):
                switch codingKey {
                case .pubKey: throw Abort(.badRequest, reason: "missing public key")
                }
            default: throw Abort(.badRequest, reason: "invalid query")
            }
        } catch let error as EncodingError {
            throw Abort(.internalServerError, reason: "unable to encode data")
        }
    }
}
