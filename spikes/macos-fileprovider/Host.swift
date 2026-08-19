// The containing app for the Phase 0c / OQ-D spike.
//
// A File Provider extension cannot register its own domain; a containing app
// must call `NSFileProviderManager.add`. This binary exists only to make that
// call and report exactly what the system answered.
//
// It prints the RAW error code rather than a description. `-2011` and `-2014`
// are different problems with the same user-facing wording, and the whole
// spike turns on telling them apart:
//
//   -2011  NSFileProviderErrorDomainDisabled       — extension found, domain
//                                                    created but user-disabled
//   -2014  NSFileProviderErrorApplicationExtensionNotFound
//                                                  — extension never discovered
//                                                    (sandbox missing, or the
//                                                    MH_BUNDLE build bug)
//
// Codes decoded from the SDK header, not guessed.

import Foundation
import FileProvider

let id = NSFileProviderDomainIdentifier(rawValue: "kr.swjeon.shepherd.spike.domain")
let domain = NSFileProviderDomain(identifier: id, displayName: "Shepherd Phase 0c Spike")
let sem = DispatchSemaphore(value: 0)

NSFileProviderManager.add(domain) { err in
    if let e = err as NSError? {
        print("REFUSED code=\(e.code) domain=\(e.domain)")
        if let u = e.userInfo[NSUnderlyingErrorKey] as? NSError {
            print("  underlying=\(u.code) domain=\(u.domain)")
        }
    } else {
        print("ACCEPTED — domain registered")
        if let m = NSFileProviderManager(for: domain) {
            m.getUserVisibleURL(for: .rootContainer) { url, e in
                if let url { print("  mounted at \(url.path)") }
                if let e { print("  no user-visible URL: \(e)") }
            }
        }
        // Leave the machine as found. A spike that registers a domain and
        // walks away leaves a mount in the user's sidebar.
        Thread.sleep(forTimeInterval: 2.0)
        NSFileProviderManager.remove(domain) { e in
            print(e == nil ? "  removed" : "  remove failed: \(e!)")
        }
    }
    sem.signal()
}

if sem.wait(timeout: .now() + 25) == .timedOut {
    print("TIMEOUT — fileproviderd never answered")
}
Thread.sleep(forTimeInterval: 1.0)
