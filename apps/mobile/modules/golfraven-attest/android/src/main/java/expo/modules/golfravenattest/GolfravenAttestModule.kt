// GolfRaven device attestation, Android half (P4.2b-2). Deliberately minimal and declarative: Play Integrity STANDARD requests, nothing else. Each function calls the
// platform API and reports its answer as { ok: true, ... } or { ok: false, code, message }; it never rejects for a platform error, hashes nothing and retries nothing
// (src/attest/native-module.ts is the contract). The requestHash is built and tested in JS against the server's recorded vector and arrives here as the base64url
// STRING Play Integrity is given. The token provider (prepareIntegrityToken) is cached per Cloud project number, and dropped after any failed request so the next
// call prepares a fresh one.
//
// [unverified] This file has NOT been compiled or run: the build environment has no Android toolchain, no Google account, no device. Written against the documented
// StandardIntegrityManager API (com.google.android.play:integrity 1.6.0).

package expo.modules.golfravenattest

import android.content.Context
import com.google.android.play.core.integrity.IntegrityManagerFactory
import com.google.android.play.core.integrity.StandardIntegrityManager
import expo.modules.kotlin.Promise
import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition

private fun failure(code: String, message: String): Map<String, Any> =
  mapOf("ok" to false, "code" to code, "message" to message)

class GolfravenAttestModule : Module() {
  private val lock = Any()
  private var provider: StandardIntegrityManager.StandardIntegrityTokenProvider? = null
  private var providerProject: Long? = null

  override fun definition() = ModuleDefinition {
    Name("GolfravenAttest")

    // Play Integrity availability is only known when a request is made, so the capability is "the module is here".
    AsyncFunction("capability") {
      return@AsyncFunction mapOf("supported" to true)
    }

    // iOS-only operations: present so the JS contract is one shape on both platforms.
    AsyncFunction("generateKey") { ->
      return@AsyncFunction failure("unsupported", "App Attest is iOS only")
    }
    AsyncFunction("attestKey") { _: String, _: String ->
      return@AsyncFunction failure("unsupported", "App Attest is iOS only")
    }
    AsyncFunction("generateAssertion") { _: String, _: String ->
      return@AsyncFunction failure("unsupported", "App Attest is iOS only")
    }
    AsyncFunction("deviceCheckToken") { ->
      return@AsyncFunction failure("unsupported", "DeviceCheck is iOS only")
    }

    AsyncFunction("integrityToken") { cloudProjectNumber: String, requestHash: String, promise: Promise ->
      val context: Context? = appContext.reactContext
      val project = cloudProjectNumber.toLongOrNull()
      if (context == null || project == null) {
        promise.resolve(failure("other", "no application context or a malformed Cloud project number"))
        return@AsyncFunction
      }
      withProvider(context, project, promise) { tokenProvider ->
        tokenProvider
          .request(StandardIntegrityManager.StandardIntegrityTokenRequest.builder().setRequestHash(requestHash).build())
          .addOnSuccessListener { response -> promise.resolve(mapOf("ok" to true, "token" to response.token())) }
          .addOnFailureListener { e ->
            synchronized(lock) { provider = null }
            promise.resolve(failure("unavailable", e.message ?: "Play Integrity request failed"))
          }
      }
    }
  }

  private fun withProvider(
    context: Context,
    project: Long,
    promise: Promise,
    use: (StandardIntegrityManager.StandardIntegrityTokenProvider) -> Unit
  ) {
    val cached = synchronized(lock) { if (providerProject == project) provider else null }
    if (cached != null) {
      use(cached)
      return
    }
    IntegrityManagerFactory.createStandard(context)
      .prepareIntegrityToken(StandardIntegrityManager.PrepareIntegrityTokenRequest.builder().setCloudProjectNumber(project).build())
      .addOnSuccessListener { prepared ->
        synchronized(lock) {
          provider = prepared
          providerProject = project
        }
        use(prepared)
      }
      .addOnFailureListener { e -> promise.resolve(failure("unavailable", e.message ?: "Play Integrity could not be prepared")) }
  }
}
