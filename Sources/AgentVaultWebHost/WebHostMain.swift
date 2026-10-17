import AgentVaultIPC
import AgentVaultWebHostProtocol
import Darwin
import Foundation

/// The `_agentvaultweb` LaunchDaemon. Production takes no arguments: identities come from the
/// protected configuration and the browser from beside this executable. It serves one broker
/// connection and exits when that connection ends, so nothing outlives a broker restart.
@main
enum WebHostMain {
    static let configurationPath = "/Library/Application Support/AgentVault/webhost.json"
    static let dataPath = "/private/var/db/agent-vault-web"
    @MainActor private static var running: (WebHostServer, HostService)?

    static func main() {
        guard geteuid() != 0, let launch = try? HostLaunch.resolve(CommandLine.arguments) else { fail() }
        let service = HostService(policy: launch.policy, binary: launch.browser, runDirectory: launch.runDirectory,
                                  onFatal: { exit(0) })
        guard let server = try? WebHostServer(configuration: launch.identity,
                                              handler: { await service.perform($0) },
                                              peerLost: { await service.teardown(); exit(0) }) else { fail() }
        Task { @MainActor in
            running = (server, service)
            server.activate()
        }
        dispatchMain()
    }

    static func fail() -> Never {
        FileHandle.standardError.write(Data("Agent Vault web host: invalid_installation\n".utf8))
        exit(1)
    }
}

struct HostLaunch {
    let identity: WebHostConfiguration
    let policy: HostPolicy
    let browser: URL
    let runDirectory: URL

    enum Failure: Error { case invalid }

    static func resolve(_ arguments: [String]) throws -> HostLaunch {
        if arguments.count == 1 { return try production() }
        #if DEBUG
        return try development(Array(arguments.dropFirst()))
        #else
        throw Failure.invalid
        #endif
    }

    /// Protected identity file, a root-owned browser beside this executable, and a private run directory.
    private static func production() throws -> HostLaunch {
        let identity = try WebHostConfiguration.load(contentsOf: WebHostMain.configurationPath)
        guard !identity.development else { throw Failure.invalid }
        try identity.validate(for: .host)
        let executable = URL(fileURLWithPath: CommandLine.arguments[0]).resolvingSymlinksInPath()
        let browser = executable.deletingLastPathComponent()
            .appendingPathComponent("chrome-headless-shell-mac-arm64/chrome-headless-shell")
        var info = stat()
        guard lstat(browser.path, &info) == 0, info.st_mode & S_IFMT == S_IFREG, info.st_uid == 0,
              info.st_mode & 0o022 == 0 else { throw Failure.invalid }
        return HostLaunch(identity: identity, policy: .production, browser: browser,
                          runDirectory: try freshRunDirectory(under: URL(fileURLWithPath: WebHostMain.dataPath)))
    }

    #if DEBUG
    /// Development builds only: `--identity <dev config> --browser <path> --fixture <loopback origin>`.
    /// The identity must be a development configuration, so this can never stand in for production.
    private static func development(_ arguments: [String]) throws -> HostLaunch {
        guard arguments.count == 6, arguments[0] == "--identity", arguments[2] == "--browser",
              arguments[4] == "--fixture", let origin = URL(string: arguments[5]),
              let policy = HostPolicy.fixture(primary: origin) else { throw Failure.invalid }
        let identity = try WebHostConfiguration.load(contentsOf: arguments[1])
        guard identity.development else { throw Failure.invalid }
        try identity.validate(for: .host)
        let base = FileManager.default.temporaryDirectory.appendingPathComponent("agentvault-webhost-\(geteuid())")
        _ = mkdir(base.path, 0o700)
        return HostLaunch(identity: identity, policy: policy, browser: URL(fileURLWithPath: arguments[3]),
                          runDirectory: try freshRunDirectory(under: base))
    }
    #endif

    /// A new 0700 directory owned by this user, inside a 0700 parent owned by this user.
    static func freshRunDirectory(under parent: URL) throws -> URL {
        var info = stat()
        guard lstat(parent.path, &info) == 0, info.st_mode & S_IFMT == S_IFDIR, info.st_uid == geteuid(),
              info.st_mode & 0o077 == 0 else { throw Failure.invalid }
        let directory = parent.appendingPathComponent("run-\(UUID().uuidString)")
        guard mkdir(directory.path, 0o700) == 0 else { throw Failure.invalid }
        return directory
    }
}
