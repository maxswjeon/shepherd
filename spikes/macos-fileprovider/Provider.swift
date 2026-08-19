// The File Provider extension principal class for the Phase 0c / OQ-D spike.
//
// Every method answers `noSuchItem`. That is deliberate and it is what the
// spike measures: the question is whether the extension is DISCOVERED by
// `pluginkit` and whether a domain REGISTERS, not whether it serves content.
// Hydration was never reached — see `FINDINGS.md`, link 3 — so a richer
// implementation would have been untested code standing in for evidence.
//
// Build: see `build.sh`. Two properties of that build are load-bearing and
// neither is obvious:
//
//   * the binary must be Mach-O `MH_EXECUTE` with `_NSExtensionMain` as its
//     entry point, NOT `MH_BUNDLE`. `codesign` SILENTLY IGNORES
//     `--entitlements` on a bundle-type Mach-O: exit 0, nothing embedded, no
//     diagnostic. Nine probes were spent on that before a control against a
//     known-good case caught it.
//   * the bundle must carry `com.apple.security.app-sandbox` or `pkd` refuses
//     it outright with "plug-ins must be sandboxed", and it never appears in
//     `pluginkit` at all.

import Foundation
import FileProvider

@objc(Provider)
final class Provider: NSObject, NSFileProviderReplicatedExtension {
    required init(domain: NSFileProviderDomain) { super.init() }

    func invalidate() {}

    func item(for id: NSFileProviderItemIdentifier, request: NSFileProviderRequest,
              completionHandler: @escaping (NSFileProviderItem?, Error?) -> Void) -> Progress {
        NSLog("[shepherd-spike] item(for:) entered — id=%@", id.rawValue)
        completionHandler(nil, NSError(domain: NSFileProviderErrorDomain,
            code: NSFileProviderError.noSuchItem.rawValue))
        return Progress()
    }

    func fetchContents(for id: NSFileProviderItemIdentifier,
                       version: NSFileProviderItemVersion?,
                       request: NSFileProviderRequest,
                       completionHandler: @escaping (URL?, NSFileProviderItem?, Error?) -> Void) -> Progress {
        NSLog("[shepherd-spike] fetchContents(for:) entered — id=%@", id.rawValue)
        completionHandler(nil, nil, NSError(domain: NSFileProviderErrorDomain,
            code: NSFileProviderError.noSuchItem.rawValue))
        return Progress()
    }

    func createItem(basedOn item: NSFileProviderItem, fields: NSFileProviderItemFields,
                    contents: URL?, options: NSFileProviderCreateItemOptions = [],
                    request: NSFileProviderRequest,
                    completionHandler: @escaping (NSFileProviderItem?, NSFileProviderItemFields, Bool, Error?) -> Void) -> Progress {
        completionHandler(nil, [], false, NSError(domain: NSFileProviderErrorDomain,
            code: NSFileProviderError.noSuchItem.rawValue))
        return Progress()
    }

    func modifyItem(_ item: NSFileProviderItem, baseVersion: NSFileProviderItemVersion,
                    changedFields: NSFileProviderItemFields, contents: URL?,
                    options: NSFileProviderModifyItemOptions = [],
                    request: NSFileProviderRequest,
                    completionHandler: @escaping (NSFileProviderItem?, NSFileProviderItemFields, Bool, Error?) -> Void) -> Progress {
        completionHandler(nil, [], false, NSError(domain: NSFileProviderErrorDomain,
            code: NSFileProviderError.noSuchItem.rawValue))
        return Progress()
    }

    func deleteItem(identifier: NSFileProviderItemIdentifier,
                    baseVersion: NSFileProviderItemVersion,
                    options: NSFileProviderDeleteItemOptions = [],
                    request: NSFileProviderRequest,
                    completionHandler: @escaping (Error?) -> Void) -> Progress {
        completionHandler(nil)
        return Progress()
    }

    func enumerator(for c: NSFileProviderItemIdentifier, request: NSFileProviderRequest)
        throws -> NSFileProviderEnumerator {
        NSLog("[shepherd-spike] enumerator(for:) entered — id=%@", c.rawValue)
        throw NSError(domain: NSFileProviderErrorDomain,
                      code: NSFileProviderError.noSuchItem.rawValue)
    }
}
