import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

/// One bounded profile response. The delegate receives chunks on Darwin and Linux;
/// it never uses an API that accumulates the entire response before checking its size.
final class BoundedProfileRequest: NSObject, URLSessionDataDelegate, @unchecked Sendable {
    private static let maximumBytes = 65_536
    private let expectedURL: URL
    private let lock = NSLock()
    private var continuation: CheckedContinuation<Data, any Error>?
    private var session: URLSession?
    private var task: URLSessionDataTask?
    private var body = Data()
    private var accepted = false
    private var finished = false

    private init(expectedURL: URL) { self.expectedURL = expectedURL }

    static func load(_ request: URLRequest, expectedURL: URL,
                     configuration: URLSessionConfiguration = .ephemeral) async throws -> Data {
        let operation = BoundedProfileRequest(expectedURL: expectedURL)
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                operation.begin(request, configuration: configuration, continuation: continuation)
            }
        } onCancel: {
            operation.finish(.failure(.upstreamUnavailable))
        }
    }

    private func begin(_ request: URLRequest, configuration: URLSessionConfiguration,
                       continuation: CheckedContinuation<Data, any Error>) {
        let admitted = lock.withLock {
            guard !finished else { return false }
            self.continuation = continuation
            return true
        }
        guard admitted else { continuation.resume(throwing: VaultError.upstreamUnavailable); return }
        configuration.httpCookieStorage = nil
        configuration.urlCredentialStorage = nil
        configuration.urlCache = nil
        configuration.timeoutIntervalForRequest = 15
        configuration.timeoutIntervalForResource = 20
        let session = URLSession(configuration: configuration, delegate: self, delegateQueue: nil)
        let task = session.dataTask(with: request)
        let start = lock.withLock {
            guard !finished else { return false }
            self.session = session; self.task = task
            return true
        }
        if start { task.resume() }
        else { task.cancel(); session.invalidateAndCancel() }
    }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive response: URLResponse,
                    completionHandler: @escaping @Sendable (URLSession.ResponseDisposition) -> Void) {
        let work = lock.withLock { () -> Completion? in
            guard !finished else { return nil }
            guard let response = response as? HTTPURLResponse, response.url == expectedURL,
                  response.statusCode == 200 else { return finishLocked(.failure(.upstreamUnavailable)) }
            guard response.expectedContentLength <= Int64(Self.maximumBytes) else {
                return finishLocked(.failure(.invalidResponse))
            }
            accepted = true
            return nil
        }
        let allow = lock.withLock { accepted && !finished }
        completionHandler(allow ? .allow : .cancel)
        deliver(work)
    }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive data: Data) {
        let work = lock.withLock { () -> Completion? in
            guard !finished else { return nil }
            guard accepted else { return finishLocked(.failure(.upstreamUnavailable)) }
            guard data.count <= Self.maximumBytes - body.count else {
                return finishLocked(.failure(.invalidResponse))
            }
            body.append(data)
            return nil
        }
        deliver(work)
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: (any Error)?) {
        let work = lock.withLock {
            finishLocked(error == nil && accepted ? .success(body) : .failure(.upstreamUnavailable))
        }
        deliver(work)
    }

    func urlSession(_ session: URLSession, task: URLSessionTask,
                    willPerformHTTPRedirection response: HTTPURLResponse, newRequest request: URLRequest,
                    completionHandler: @escaping @Sendable (URLRequest?) -> Void) {
        RejectRedirects().urlSession(session, task: task, willPerformHTTPRedirection: response,
                                    newRequest: request, completionHandler: completionHandler)
    }

    private struct Completion {
        let continuation: CheckedContinuation<Data, any Error>?
        let session: URLSession?
        let task: URLSessionDataTask?
        let result: Result<Data, VaultError>
    }

    private func finish(_ result: Result<Data, VaultError>) {
        let work = lock.withLock { finishLocked(result) }
        deliver(work)
    }

    /// Called only under the lock. Session APIs and continuation resumption run after unlocking.
    private func finishLocked(_ result: Result<Data, VaultError>) -> Completion? {
        guard !finished else { return nil }
        finished = true
        let work = Completion(continuation: continuation, session: session, task: task, result: result)
        continuation = nil; session = nil; task = nil; body = Data()
        return work
    }

    private func deliver(_ work: Completion?) {
        guard let work else { return }
        work.task?.cancel()
        work.session?.invalidateAndCancel()
        work.continuation?.resume(with: work.result.mapError { $0 as any Error })
    }
}
