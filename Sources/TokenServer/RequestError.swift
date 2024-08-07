public enum TokenServerRequestError: Error, Hashable, Codable {
    case unableToDecodeQuery
    case invalidSignature
    case missingSignature
}
