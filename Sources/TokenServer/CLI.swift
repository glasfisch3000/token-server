import ArgumentParser
import Vapor

@main
public struct TokenServerCLI: AsyncParsableCommand {
    public static var configuration = CommandConfiguration(
        commandName: "token-server",
        version: "1.0.0"
    )
    
    @ArgumentParser.Option(name: .customLong("inactive-domain-timeout")) public var inactiveDomainTimeout: TimeInterval = 60*60*24 // 1 day
    @ArgumentParser.Option(name: .customLong("signature-timestamp-tolerance")) public var signatureTimestampTolerance: TimeInterval = 10
    
    public init() {}
    
    public func run() async throws {
        let configuration = TokenServer.Configuration(inactiveDomainTimeout: inactiveDomainTimeout, 
                                                      signatureTimestampTolerance: signatureTimestampTolerance)
        
        var env = try Environment.detect()
        try LoggingSystem.bootstrap(from: &env)
        
        let app = Application(env)
        defer { app.shutdown() }
        
        do {
            app.logger.debug("initializing server")
            let server = TokenServer(app: app, config: configuration)
            
            app.logger.debug("configuring server")
            try await server.configure()
            
            app.logger.debug("starting server")
            try await server.run()
        } catch {
            app.logger.report(error: error)
            throw error
        }
    }
}
