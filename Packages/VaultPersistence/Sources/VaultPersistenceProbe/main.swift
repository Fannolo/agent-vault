// TEST-ONLY separate-process probe for lease and crash-cut tests. It opens only the roots it
// is given, writes only synthetic bytes, and kills only itself (SIGKILL at a requested cut).
import CSQLite
import Foundation
import VaultPersistence
import VaultPersistenceTestSupport
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif

func emit(_ line: String) { FileHandle.standardOutput.write(Data((line + "\n").utf8)) }

func dieNow() -> Never {
    kill(getpid(), SIGKILL)
    while true { pause() }
}

let arguments = CommandLine.arguments
guard arguments.count >= 4 else {
    emit("USAGE hold|commit|fill|info ROOT PINDIR ...")
    exit(64)
}
let (command, root, pinDirectory) = (arguments[1], arguments[2], arguments[3])
let pin = TestOnlyFileCustodyPin(directory: pinDirectory)

@MainActor func openKernel() -> VaultKernel {
    do {
        return try VaultKernel.openExisting(root: root, custody: pin)
    } catch .busy {
        emit("BUSY")
        exit(3)
    } catch {
        emit("LOCKED \(error)")
        exit(4)
    }
}

@MainActor func number(_ index: Int) -> Int {
    guard arguments.count > index, let value = Int(arguments[index]) else {
        emit("USAGE bad argument \(index)")
        exit(64)
    }
    return value
}

switch command {
case "create":
    try TestOnlyFileCustodyPin.provision(directory: pinDirectory)
    let kernel = try VaultKernel.create(root: root, initial: Synthetic.state(seed: 1), custody: pin)
    emit("CREATED \(kernel.head.state)")
    exit(0)

case "tiny-create":
    try TestOnlyFileCustodyPin.provision(directory: pinDirectory)
    let kernel = try VaultKernel.create(root: root, initial: SealedState(frame: [0x41]), custody: pin)
    emit("CREATED \(kernel.head.state)")
    exit(0)

case "tiny-commit":
    // Fixed synthetic counterexample vocabulary. Never a production/public interface.
    guard arguments.count == 7,
          ["none", "afterDatabaseCommit", "prepareFault"].contains(arguments[4]),
          ["B", "C"].contains(arguments[5]), ["none", "X", "Y"].contains(arguments[6]) else { exit(64) }
    let kernel = openKernel()
    let frame = SealedState(frame: arguments[5] == "B" ? [0x42] : [0x43])
    let objects: [SignedObject] = arguments[6] == "none" ? []
        : [SignedObject(bytes: arguments[6] == "X" ? [0x58] : [0x59])]
    if arguments[4] == "afterDatabaseCommit" { pin.crashAt = .beforeFinish }
    if arguments[4] == "prepareFault" { pin.fault = .prepareAfterPersist }
    do {
        let head = try kernel.commit(expecting: kernel.head, next: frame, adding: objects)
        emit("ACK \(head.generation) \(head.state)")
        exit(0)
    } catch {
        emit("ERROR \(error)")
        exit(5)
    }

case "hold":
    let kernel = openKernel()
    emit("OPEN \(kernel.head.generation)")
    sleep(3)
    withExtendedLifetime(kernel) {}
    exit(0)

case "commit":
    // commit ROOT PIN CUT SEED COUNT SIZE DUPLICATE_SEED
    let cut = arguments.count > 4 ? arguments[4] : ""
    let crashPoints: [String: TestOnlyFileCustodyPin.CrashPoint] = [
        "beforePending": .beforePrepare, "afterPending": .afterPrepare,
        "afterDatabaseCommit": .beforeFinish, "afterStablePin": .afterFinish,
    ]
    guard crashPoints[cut] != nil || cut == "afterReturn" || cut == "none" else {
        emit("USAGE bad cut")
        exit(64)
    }
    let seed = UInt64(number(5))
    let objects = Synthetic.objects(seed: UInt64(number(8)), count: 1, size: number(7))
        + Synthetic.objects(seed: seed, count: number(6), size: number(7))
    let kernel = openKernel()
    emit("OPENED \(kernel.head.generation) \(kernel.head.state)")
    pin.crashAt = crashPoints[cut]
    do {
        let head = try kernel.commit(expecting: kernel.head, next: Synthetic.state(seed: seed), adding: objects)
        emit("ACK \(head.generation) \(head.state)")
        if cut == "afterReturn" { dieNow() }
        exit(0)
    } catch {
        emit("ERROR \(error)")
        exit(5)
    }

case "fill":
    // fill ROOT PIN SEED SIZE HEADROOM: real write() failure via RLIMIT_FSIZE.
    let seed = UInt64(number(4))
    let kernel = openKernel()
    var status = stat()
    guard stat(root + "/" + VaultKernel.databaseName, &status) == 0 else { exit(66) }
    signal(SIGXFSZ, SIG_IGN)
    let ceiling = rlim_t(Int(status.st_size) + number(6))
    var limit = rlimit(rlim_cur: ceiling, rlim_max: ceiling)
    #if canImport(Darwin)
    let resource = RLIMIT_FSIZE
    #else
    let resource = __rlimit_resource_t(RLIMIT_FSIZE.rawValue)
    #endif
    guard setrlimit(resource, &limit) == 0 else { exit(71) }
    emit("LIMIT \(ceiling)")
    do {
        let head = try kernel.commit(expecting: kernel.head, next: Synthetic.state(seed: seed),
                                     adding: Synthetic.objects(seed: seed, count: 1, size: number(5)))
        emit("ACK \(head.generation) \(head.state)")
    } catch {
        emit("FAILED \(error)")
    }
    do {
        let head = try kernel.commit(expecting: kernel.head, next: Synthetic.state(seed: seed + 1), adding: [])
        emit("SECOND-ACK \(head.generation)")
    } catch {
        emit("SECOND \(error)")
    }
    exit(0)

case "info":
    let kernel = openKernel()
    let runtime = SQLiteRuntime.current()
    let settings = kernel.settings
    var image = "unknown"
    #if canImport(Darwin)
    var info = Dl_info()
    let function: @convention(c) () -> UnsafePointer<CChar>? = sqlite3_libversion
    if dladdr(unsafeBitCast(function, to: UnsafeRawPointer.self), &info) != 0, let name = info.dli_fname {
        image = String(cString: name)
    }
    #else
    if let maps = try? String(contentsOfFile: "/proc/self/maps", encoding: .utf8) {
        image = Set(maps.split(separator: "\n").compactMap { line in
            line.split(separator: " ").last.map(String.init)
        }.filter { $0.contains("libsqlite3") }).sorted().joined(separator: ",")
    }
    #endif
    let report: [String: Any] = [
        "library_version": runtime.libraryVersion, "library_source_id": runtime.librarySourceID,
        "header_version": runtime.headerVersion, "header_source_id": runtime.headerSourceID,
        "compile_options": runtime.compileOptions, "library_image": image,
        "settings": ["journal_mode": settings.journalMode, "synchronous": settings.synchronous,
                     "fullfsync": settings.fullFsync, "foreign_keys": settings.foreignKeys,
                     "trusted_schema": settings.trustedSchema, "temp_store": settings.tempStore,
                     "load_extension": Int(settings.loadExtension), "defensive": Int(settings.defensive)],
    ]
    let data = try JSONSerialization.data(withJSONObject: report, options: [.sortedKeys, .prettyPrinted])
    FileHandle.standardOutput.write(data)
    emit("")
    exit(0)

default:
    emit("USAGE unknown command")
    exit(64)
}
