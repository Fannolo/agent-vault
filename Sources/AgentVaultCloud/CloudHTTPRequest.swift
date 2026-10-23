import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

struct CloudHTTPResponse: Sendable { let status: Int; let body: Data }

/// Private fixed-route adapter support. Rejects redirects and bounds body chunks before append.
final class CloudHTTPRequest: NSObject, URLSessionDataDelegate, @unchecked Sendable {
    static let maximumBytes = 8 * 1024 * 1024
    private let expectedURL: URL
    private let lock = NSLock()
    private var continuation: CheckedContinuation<CloudHTTPResponse, any Error>?
    private var session: URLSession?
    private var task: URLSessionDataTask?
    private var body = Data()
    private var status: Int?
    private var finished = false

    private init(url: URL) { expectedURL = url }

    static func load(_ request: URLRequest, configuration: URLSessionConfiguration) async throws -> CloudHTTPResponse {
        guard let url = request.url else { throw CloudError.invalidConfiguration }
        let operation = CloudHTTPRequest(url: url)
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { continuation in
                operation.begin(request, configuration: configuration, continuation: continuation)
            }
        } onCancel: { operation.finish(.failure(.unavailable)) }
    }

    private func begin(_ request: URLRequest, configuration: URLSessionConfiguration,
                       continuation: CheckedContinuation<CloudHTTPResponse, any Error>) {
        let admitted = lock.withLock {
            guard !finished else { return false }
            self.continuation = continuation
            return true
        }
        guard admitted else { continuation.resume(throwing: CloudError.unavailable); return }
        configuration.httpCookieStorage = nil; configuration.urlCredentialStorage = nil; configuration.urlCache = nil
        configuration.timeoutIntervalForRequest = 15; configuration.timeoutIntervalForResource = 20
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
                  response.expectedContentLength <= Int64(Self.maximumBytes) else {
                return finishLocked(.failure(.invalidResponse))
            }
            status = response.statusCode
            return nil
        }
        let allow = lock.withLock { status != nil && !finished }
        completionHandler(allow ? .allow : .cancel)
        deliver(work)
    }

    func urlSession(_ session: URLSession, dataTask: URLSessionDataTask, didReceive data: Data) {
        let work = lock.withLock { () -> Completion? in
            guard !finished else { return nil }
            guard status != nil, data.count <= Self.maximumBytes - body.count else {
                return finishLocked(.failure(.invalidResponse))
            }
            body.append(data)
            return nil
        }
        deliver(work)
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, didCompleteWithError error: (any Error)?) {
        let work = lock.withLock {
            if error == nil, let status { return finishLocked(.success(.init(status: status, body: body))) }
            return finishLocked(.failure(.unavailable))
        }
        deliver(work)
    }

    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                    newRequest request: URLRequest, completionHandler: @escaping @Sendable (URLRequest?) -> Void) {
        completionHandler(nil)
        finish(.failure(.invalidResponse))
    }

    private struct Completion {
        let continuation: CheckedContinuation<CloudHTTPResponse, any Error>?
        let session: URLSession?
        let task: URLSessionDataTask?
        let result: Result<CloudHTTPResponse, CloudError>
    }

    private func finish(_ result: Result<CloudHTTPResponse, CloudError>) {
        deliver(lock.withLock { finishLocked(result) })
    }

    private func finishLocked(_ result: Result<CloudHTTPResponse, CloudError>) -> Completion? {
        guard !finished else { return nil }
        finished = true
        let work = Completion(continuation: continuation, session: session, task: task, result: result)
        continuation = nil; session = nil; task = nil; body = Data()
        return work
    }

    private func deliver(_ work: Completion?) {
        guard let work else { return }
        work.task?.cancel(); work.session?.invalidateAndCancel()
        work.continuation?.resume(with: work.result.mapError { $0 as any Error })
    }
}
