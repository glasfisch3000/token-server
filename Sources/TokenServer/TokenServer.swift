import Vapor
import Logging

public final actor TokenServer: Sendable {
    public struct Configuration: Hashable, Codable {
        public var inactiveDomainTimeout: TimeInterval
        public var signatureTimestampTolerance: TimeInterval
    }
    
    public let application: Application
    public let configuration: Configuration
    public var tokens: [UUID: TokenStorage]
    
    public init(app: Application, config: Configuration) {
        self.application = app
        self.configuration = config
        self.tokens = [:]
    }
    
    public func configure() async throws {
        application.get { req async in
            Response(status: .ok, body: "ready")
        }
        
        application.get(.catchall) { req async in
            Response(status: .notFound, body: "notFound")
        }
        
        application.get("domain", use: self.getDomain(_:))
        application.post("domain", use: self.revalidateDomain(_:))
        application.put("domain", use: self.createDomain(_:))
        application.delete("domain", use: self.deleteDomain(_:))
        application.get("token", use: self.getToken(_:))
        application.put("token", use: self.setToken(_:))
        application.delete("token", use: self.deleteToken(_:))
        
        application.http.server.configuration.port = 5555
    }
    
    public func run() async throws {
        try await application.startup()
        
        application.logger.info("server is running on port \(application.http.server.configuration.port)")
        try await application.running?.onStop.get()
    }
}
