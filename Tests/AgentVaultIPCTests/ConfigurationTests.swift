@testable import AgentVaultIPC
import Foundation
import Testing

@Test func developmentFixturePinnedToCDHashIsAccepted() throws {
    try developmentConfiguration().validate(for: .broker)
    try developmentConfiguration().validate(for: .readClient)
}

@Test func productionRefusesSameBrokerAndClientUID() throws {
    try productionConfiguration().validate(for: .broker, effectiveUID: 260)
    try productionConfiguration().validate(for: .readClient, effectiveUID: 501)
    #expect(throws: IPCError.invalidConfiguration) {
        try productionConfiguration(brokerUID: 501, allowedUID: 501).validate(for: .broker, effectiveUID: 501)
    }
}

@Test func rootIsRefusedInEveryRoleAndMode() {
    #expect(throws: IPCError.invalidConfiguration) {
        try productionConfiguration(brokerUID: 0).validate(for: .broker, effectiveUID: 0)
    }
    #expect(throws: IPCError.invalidConfiguration) {
        try productionConfiguration(allowedUID: 0).validate(for: .readClient, effectiveUID: 0)
    }
    #expect(throws: IPCError.invalidConfiguration) {
        try developmentConfiguration(brokerUID: 0, allowedUID: 0).validate(for: .broker, effectiveUID: 0)
    }
}

@Test func processMustRunAsTheUIDOfItsRole() {
    #expect(throws: IPCError.invalidConfiguration) {
        try productionConfiguration().validate(for: .broker, effectiveUID: 501)
    }
    #expect(throws: IPCError.invalidConfiguration) {
        try productionConfiguration().validate(for: .adminClient, effectiveUID: 260)
    }
}

@Test func weakenedOrAmbiguousRequirementsAreRefused() {
    let pin = pinned()
    let cases: [IPCConfiguration] = [
        developmentConfiguration(read: pin.broker),
        developmentConfiguration(read: "\(pin.read) or always"),
        developmentConfiguration(read: "always"),
        developmentConfiguration(read: "! cdhash H\"\(wrongCDHash)\""),
        developmentConfiguration(read: "identifier \"dev.agentvault.bridge\""),
        developmentConfiguration(read: "cdhash H\"zz\" and"),
        developmentConfiguration(read: "")
    ]
    for configuration in cases {
        #expect(throws: IPCError.invalidConfiguration) { try configuration.validate(for: .broker) }
    }
    var production = productionConfiguration()
    production.readRequirement = #"anchor apple generic and identifier "com.bitetechnology.agentvault.bridge""#
    #expect(throws: IPCError.invalidConfiguration) { try production.validate(for: .broker, effectiveUID: 260) }
}

@Test func serviceNamesMustBeDistinctReverseDNS() {
    var configuration = developmentConfiguration()
    configuration.adminServiceName = configuration.readServiceName
    #expect(throws: IPCError.invalidConfiguration) { try configuration.validate(for: .broker) }
    configuration.adminServiceName = "bad name"
    #expect(throws: IPCError.invalidConfiguration) { try configuration.validate(for: .broker) }
}

private func temporaryFile(_ contents: Data) throws -> String {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent("agentvault-ipc-tests-\(UUID())")
    try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: false)
    let path = directory.appendingPathComponent("ipc.json").path
    #expect(FileManager.default.createFile(atPath: path, contents: contents))
    return path
}

private func remove(_ path: String) {
    try? FileManager.default.removeItem(atPath: (path as NSString).deletingLastPathComponent)
}

@Test func loaderReadsDevelopmentFileAndRejectsUnknownKeys() throws {
    let encoded = try JSONEncoder().encode(developmentConfiguration())
    let path = try temporaryFile(encoded)
    defer { remove(path) }
    #expect(try IPCConfiguration.load(contentsOf: path) == developmentConfiguration())

    var object = try #require(try JSONSerialization.jsonObject(with: encoded) as? [String: Any])
    object["extraService"] = "dev.agentvault.other"
    let extra = try temporaryFile(try JSONSerialization.data(withJSONObject: object))
    defer { remove(extra) }
    #expect(throws: IPCError.invalidConfiguration) { try IPCConfiguration.load(contentsOf: extra) }
}

@Test func loaderRefusesUserWritableProductionFileAndSymlinks() throws {
    let path = try temporaryFile(try JSONEncoder().encode(productionConfiguration()))
    defer { remove(path) }
    #expect(throws: IPCError.invalidConfiguration) { try IPCConfiguration.load(contentsOf: path) }

    let development = try temporaryFile(try JSONEncoder().encode(developmentConfiguration()))
    defer { remove(development) }
    let link = (development as NSString).deletingLastPathComponent + "/link.json"
    try FileManager.default.createSymbolicLink(atPath: link, withDestinationPath: development)
    #expect(throws: IPCError.invalidConfiguration) { try IPCConfiguration.load(contentsOf: link) }
}

@Test func productionTemplateValidatesOnceUIDsAreFilled() throws {
    let template = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        .appendingPathComponent("../../deploy/ipc/ipc.json.template")
    let text = try String(contentsOf: template, encoding: .utf8)
        .replacingOccurrences(of: "@BROKER_UID@", with: "260").replacingOccurrences(of: "@CLIENT_UID@", with: "501")
    let configuration = try JSONDecoder().decode(IPCConfiguration.self, from: Data(text.utf8))
    try configuration.validate(for: .broker, effectiveUID: 260)
    try configuration.validate(for: .readClient, effectiveUID: 501)
    var sameUID = configuration
    sameUID.brokerUID = 501
    #expect(throws: IPCError.invalidConfiguration) { try sameUID.validate(for: .readClient, effectiveUID: 501) }
}
