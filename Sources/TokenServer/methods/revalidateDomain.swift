import Vapor
import TokenServerAuth

extension TokenServer {
    private struct RevalidateDomainRequestParameters: Decodable {
        enum CodingKeys: CodingKey {
            case domain
        }
        
        var domain: UUID
    }
    
    @Sendable
    public func revalidateDomain(_ request: Request) async throws -> Response {
        do {
            let params = try request.query.decode(RevalidateDomainRequestParameters.self)
            
            guard let date = self.tokens[params.domain]?.revalidate(self.configuration.inactiveDomainTimeout) else {
                throw Abort(.notFound, reason: "unknown domain")
            }
            
            let responseData = try JSONEncoder().encode(date)
            return Response(status: .ok, body: .init(data: responseData))
        } catch let error as DecodingError {
            switch error {
            case .keyNotFound(let codingKey as RevalidateDomainRequestParameters.CodingKeys, _):
                switch codingKey {
                case .domain: throw Abort(.badRequest, reason: "missing domain")
                }
            default: throw Abort(.badRequest, reason: "invalid query")
            }
        } catch _ as EncodingError {
            throw Abort(.internalServerError, reason: "unable to encode data")
        }
    }
}
