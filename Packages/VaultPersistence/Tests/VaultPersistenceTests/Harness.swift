import Foundation
import Testing
import VaultPersistence
import VaultPersistenceTestSupport
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

/// One private canonical temporary tree per test: `vault/` (kernel root) and a separate
/// `custody/` holding the test-only pin. Removes only the tree it created.
final class Sandbox {
    let base: String
    let root: String
    let pinDirectory: String

    init() throws {
        var template = Array((FileManager.default.temporaryDirectory.path + "/avp-XXXXXX").utf8CString)
        guard let made = mkdtemp(&template), let resolved = realpath(made, nil) else {
            throw POSIXError(.EIO)
        }
        base = String(cString: resolved)
        free(resolved)
        root = base + "/vault"
        pinDirectory = base + "/custody"
        for directory in [base, root, pinDirectory] {
            mkdir(directory, 0o700)
            chmod(directory, 0o700)
        }
        try TestOnlyFileCustodyPin.provision(directory: pinDirectory)
    }

    deinit {
        chmod(base, 0o700)
        try? FileManager.default.removeItem(atPath: base)
    }

    var database: String { root + "/" + VaultKernel.databaseName }
    var journal: String { database + "-journal" }
    var lease: String { root + "/" + VaultKernel.leaseName }
    func pin(crashAt: TestOnlyFileCustodyPin.CrashPoint? = nil,
             fault: TestOnlyFileCustodyPin.Fault? = nil) -> TestOnlyFileCustodyPin {
        TestOnlyFileCustodyPin(directory: pinDirectory, crashAt: crashAt, fault: fault)
    }

    func create(seed: UInt64 = 1, limits: KernelLimits = .standard) throws(PersistenceError) -> VaultKernel {
        try VaultKernel.create(root: root, initial: Synthetic.state(seed: seed), custody: pin(), limits: limits)
    }

    func open(limits: KernelLimits = .standard, fault: TestOnlyFileCustodyPin.Fault? = nil)
        throws(PersistenceError) -> VaultKernel {
        try VaultKernel.openExisting(root: root, custody: pin(fault: fault), limits: limits)
    }

    func pinRecord() throws -> PinRecord { try TestOnlyFileCustodyPin.load(directory: pinDirectory) }

    func entries() -> Set<String> { Set((try? FileManager.default.contentsOfDirectory(atPath: root)) ?? []) }

    func exists(_ path: String) -> Bool {
        var status = stat()
        return lstat(path, &status) == 0
    }

    func bytes(_ path: String) -> [UInt8] { [UInt8](FileManager.default.contents(atPath: path) ?? Data()) }

    /// Replaces a file's contents in place, keeping its inode and mode.
    func overwrite(_ path: String, _ bytes: [UInt8]) {
        let descriptor = posixOpen(path, O_WRONLY | O_TRUNC)
        precondition(descriptor >= 0)
        _ = bytes.withUnsafeBytes { write(descriptor, $0.baseAddress, $0.count) }
        fsync(descriptor)
        close(descriptor)
    }

    func mode(_ path: String) -> UInt32 {
        var status = stat()
        guard lstat(path, &status) == 0 else { return 0 }
        return UInt32(status.st_mode) & 0o7777
    }
}

// `Sandbox.open` shadows the POSIX function inside the class.
private func posixOpen(_ path: String, _ flags: Int32) -> Int32 { open(path, flags) }

/// The kernel error thrown by `body`, or nil when it succeeds.
func failure<T>(_ body: () throws -> T) -> PersistenceError? {
    do {
        _ = try body()
        return nil
    } catch {
        guard let known = error as? PersistenceError else {
            Issue.record("Unexpected non-kernel error")
            return nil
        }
        return known
    }
}
