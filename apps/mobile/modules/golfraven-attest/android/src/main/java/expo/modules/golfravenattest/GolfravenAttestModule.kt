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
import android.provider.Settings
import com.google.android.play.core.integrity.IntegrityManagerFactory
import com.google.android.play.core.integrity.StandardIntegrityManager
import com.google.android.play.core.integrity.StandardIntegrityException
import expo.modules.kotlin.Promise
import expo.modules.kotlin.modules.Module
import expo.modules.kotlin.modules.ModuleDefinition

private fun failure(code: String, message: String): Map<String, Any> =
  mapOf("ok" to false, "code" to code, "message" to message)

// Play Integrity error codes (StandardIntegrityErrorCode / the documented table) [unverified: not checked against the library]. PERMANENT on this device, so asking again cannot
// help: API_NOT_AVAILABLE (-1), PLAY_STORE_NOT_FOUND (-2), PLAY_SERVICES_NOT_FOUND (-6), APP_NOT_INSTALLED (-5), APP_UID_MISMATCH (-7) -> "unsupported".
// Everything else (network, Play Store account, too many requests, Google server, a stale provider, internal) is transient -> "unavailable".
private val PERMANENT_CODES = setOf(-1, -2, -5, -6, -7)

private fun failureFrom(e: Exception, fallback: String): Map<String, Any> {
  val code = (e as? StandardIntegrityException)?.errorCode
  val message = e.message ?: fallback
  return if (code != null && code in PERMANENT_CODES) failure("unsupported", message) else failure("unavailable", message)
}

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

    // P4.2b-3b, reward activation only: the install link id the server links device rows on for the Android substitute of the persistent bits (A20). The SSAID
    // (Settings.Secure.ANDROID_ID: scoped to the app signing key, the user and the device, kept across a reinstall of an app signed with the same key, reset by a factory
    // reset) [unverified: platform behaviour from the documented meaning, not observed]. It needs no permission. The server stores only its SHA-256 and the id is bound
    // into the Play Integrity request hash. A null / empty value, or the known-broken constant some old emulators report, is "unsupported": no id is better than a shared one.
    AsyncFunction("installLinkId") { ->
      try {
        val context: Context? = appContext.reactContext
        val id: String? = if (context == null) null else Settings.Secure.getString(context.contentResolver, Settings.Secure.ANDROID_ID)
        if (id == null || id.length < 16 || id == "9774d56d682e549c") {
          return@AsyncFunction failure("unsupported", "no usable install link id on this device")
        }
        return@AsyncFunction mapOf("ok" to true, "installLinkId" to id)
      } catch (e: Exception) {
        return@AsyncFunction failure("other", e.message ?: "install link id threw")
      }
    }

    AsyncFunction("integrityToken") { cloudProjectNumber: String, requestHash: String, promise: Promise ->
      // Nothing here may throw into the bridge: every synchronous call is guarded and every failure resolves { ok: false }.
      try {
        val context: Context? = appContext.reactContext
        val project = cloudProjectNumber.toLongOrNull()
        if (context == null || project == null) {
          promise.resolve(failure("other", "no application context or a malformed Cloud project number"))
          return@AsyncFunction
        }
        withProvider(context, project, promise) { tokenProvider ->
          try {
            tokenProvider
              .request(StandardIntegrityManager.StandardIntegrityTokenRequest.builder().setRequestHash(requestHash).build())
              .addOnSuccessListener { response -> promise.resolve(mapOf("ok" to true, "token" to response.token())) }
              .addOnFailureListener { e ->
                synchronized(lock) { provider = null }
                promise.resolve(failureFrom(e, "Play Integrity request failed"))
              }
          } catch (e: Exception) {
            synchronized(lock) { provider = null }
            promise.resolve(failureFrom(e, "Play Integrity request threw"))
          }
        }
      } catch (e: Exception) {
        promise.resolve(failureFrom(e, "Play Integrity call threw"))
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
    try {
      IntegrityManagerFactory.createStandard(context)
        .prepareIntegrityToken(StandardIntegrityManager.PrepareIntegrityTokenRequest.builder().setCloudProjectNumber(project).build())
        .addOnSuccessListener { prepared ->
          synchronized(lock) {
            provider = prepared
            providerProject = project
          }
          use(prepared)
        }
        .addOnFailureListener { e -> promise.resolve(failureFrom(e, "Play Integrity could not be prepared")) }
    } catch (e: Exception) {
      promise.resolve(failureFrom(e, "Play Integrity could not be prepared"))
    }
  }
}
