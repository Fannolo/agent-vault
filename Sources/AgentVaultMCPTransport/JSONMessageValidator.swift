import AgentVaultJSON
import Foundation

enum JSONMessageValidator {
    static func validate(_ data: Data) throws {
        do { try JSONObjectGuard.validate(data, mode: .jsonRPC) }
        catch let failure as JSONObjectGuard.Failure {
            switch failure {
            case .invalidJSON: throw StdioTransportError.invalidJSON
            case .tooDeep: throw StdioTransportError.tooDeep
            case .duplicateKey: throw StdioTransportError.duplicateKey
            case .invalidRequestID: throw StdioTransportError.invalidRequestID
            }
        }
    }
}
