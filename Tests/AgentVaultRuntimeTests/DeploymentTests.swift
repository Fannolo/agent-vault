import AgentVaultRuntime
import Darwin
import Foundation
import Testing

private func directory() throws -> URL {
    let url = FileManager.default.temporaryDirectory.appendingPathComponent("agent-vault-runtime-\(UUID())")
    try FileManager.default.createDirectory(at: url, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    return url
}

@Test func leaseDeniesAnotherOwnerUntilReleased() throws {
    let root = try directory()
    defer { try? FileManager.default.removeItem(at: root) }
    var first: BrokerLease? = try BrokerLease(directory: root)
    #expect(first != nil)
    #expect(throws: DeploymentError.alreadyRunning) { _ = try BrokerLease(directory: root) }
    first = nil
    _ = try BrokerLease(directory: root)
}

@Test func protectedMaterialRefusesSymlinksPermissionsSizeAndWrongOwner() throws {
    let root = try directory()
    defer { try? FileManager.default.removeItem(at: root) }
    let path = root.appendingPathComponent("fixture")
    let value = Data(repeating: 0x42, count: 32)
    try value.write(to: path)
    try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: path.path)
    #expect(try ProtectedFiles.read(path, owner: geteuid(), maximum: 32) == value)
    #expect(throws: DeploymentError.invalidInstallation) { _ = try ProtectedFiles.read(path, owner: geteuid() + 1, maximum: 32) }
    #expect(throws: DeploymentError.invalidInstallation) { _ = try ProtectedFiles.read(path, owner: geteuid(), maximum: 31) }
    let link = root.appendingPathComponent("link")
    try FileManager.default.createSymbolicLink(at: link, withDestinationURL: path)
    #expect(throws: DeploymentError.invalidInstallation) { _ = try ProtectedFiles.read(link, owner: geteuid(), maximum: 32) }
    try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: path.path)
    #expect(throws: DeploymentError.invalidInstallation) { _ = try ProtectedFiles.read(path, owner: geteuid(), maximum: 32) }
}
