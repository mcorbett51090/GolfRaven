// GolfRaven device attestation, iOS half (P4.2b-2). Deliberately minimal and declarative: each function calls ONE platform API and reports its answer as
// `{ ok: true, ... }` or `{ ok: false, code, message }`. It never rejects for a platform error, hashes nothing, keeps no state and retries nothing: the byte layouts
// that are bound (`clientDataHash`) are built and tested in JS (`apps/mobile/src/attest/binding.ts`, against the server's recorded vectors) and arrive here as
// base64 of the 32 hash bytes. Result shapes: `src/attest/native-module.ts`.
//
// [unverified] This file has NOT been compiled or run: the build environment has no Xcode, no Apple account, no device. It type-checks only in the
// author's head against the documented DeviceCheck API (`DCAppAttestService`, `DCDevice`, `DCError`).

import DeviceCheck
import ExpoModulesCore

private func ok(_ fields: [String: Any]) -> [String: Any] {
  var out = fields
  out["ok"] = true
  return out
}

private func failure(_ code: String, _ message: String) -> [String: Any] {
  return ["ok": false, "code": code, "message": message]
}

/// Maps a DeviceCheck error to the closed set of codes the JS side switches on. `invalid_key` is the one that matters: the key is gone (a reinstall destroys it).
private func failure(from error: Error?) -> [String: Any] {
  guard let error = error else { return failure("other", "unknown error") }
  if let dc = error as? DCError {
    switch dc.code {
    case .invalidKey:
      return failure("invalid_key", "App Attest key is invalid")
    case .serverUnavailable:
      // Reported as "unavailable" so the JS layer keeps the SAME key and retries `attestKey` with it (Apple: retry with the same key after serverUnavailable; do not
      // generate another). The key id is remembered by `src/attest/state-store.ts` (`getUnattestedKey`); this file keeps no state.
      return failure("unavailable", "Apple attestation service unavailable")
    case .featureUnsupported:
      return failure("unsupported", "App Attest is not supported")
    default:
      return failure("other", "DeviceCheck error \(dc.code.rawValue)")
    }
  }
  return failure("other", error.localizedDescription)
}

private func hashData(_ base64: String) -> Data? {
  guard let data = Data(base64Encoded: base64), data.count == 32 else { return nil }
  return data
}

public class GolfravenAttestModule: Module {
  public func definition() -> ModuleDefinition {
    Name("GolfravenAttest")

    AsyncFunction("capability") { () -> [String: Any] in
      return ["supported": DCAppAttestService.shared.isSupported]
    }

    AsyncFunction("generateKey") { (promise: Promise) in
      guard DCAppAttestService.shared.isSupported else {
        promise.resolve(failure("unsupported", "App Attest is not supported on this device"))
        return
      }
      DCAppAttestService.shared.generateKey { keyId, error in
        if let keyId = keyId {
          promise.resolve(ok(["keyId": keyId]))
        } else {
          promise.resolve(failure(from: error))
        }
      }
    }

    AsyncFunction("attestKey") { (keyId: String, clientDataHash: String, promise: Promise) in
      guard let hash = hashData(clientDataHash) else {
        promise.resolve(failure("other", "clientDataHash must be base64 of 32 bytes"))
        return
      }
      DCAppAttestService.shared.attestKey(keyId, clientDataHash: hash) { attestation, error in
        if let attestation = attestation {
          promise.resolve(ok(["attestation": attestation.base64EncodedString()]))
        } else {
          promise.resolve(failure(from: error))
        }
      }
    }

    AsyncFunction("generateAssertion") { (keyId: String, clientDataHash: String, promise: Promise) in
      guard let hash = hashData(clientDataHash) else {
        promise.resolve(failure("other", "clientDataHash must be base64 of 32 bytes"))
        return
      }
      DCAppAttestService.shared.generateAssertion(keyId, clientDataHash: hash) { assertion, error in
        if let assertion = assertion {
          promise.resolve(ok(["assertion": assertion.base64EncodedString()]))
        } else {
          promise.resolve(failure(from: error))
        }
      }
    }

    AsyncFunction("deviceCheckToken") { (promise: Promise) in
      guard DCDevice.current.isSupported else {
        promise.resolve(failure("unsupported", "DeviceCheck is not supported on this device"))
        return
      }
      DCDevice.current.generateToken { token, error in
        if let token = token {
          promise.resolve(ok(["token": token.base64EncodedString()]))
        } else {
          promise.resolve(failure(from: error))
        }
      }
    }

    // Android-only operations: present so the JS contract is one shape on both platforms.
    AsyncFunction("integrityToken") { (cloudProjectNumber: String, requestHash: String) -> [String: Any] in
      return failure("unsupported", "Play Integrity is Android only")
    }

    AsyncFunction("installLinkId") { () -> [String: Any] in
      return failure("unsupported", "The install link id is Android only")
    }
  }
}
