package com.msnguard.vpn.foxy

import java.lang.reflect.Proxy
import okhttp3.Interceptor
import okhttp3.Protocol
import okhttp3.Request
import okhttp3.Response
import okhttp3.ResponseBody.Companion.toResponseBody
import org.junit.Assert.*
import org.junit.Test

class FoxyRelayerTest {
    private fun chain(request: Request, proceed: (Request) -> Response): Interceptor.Chain =
        Proxy.newProxyInstance(Interceptor.Chain::class.java.classLoader,
            arrayOf(Interceptor.Chain::class.java)) { proxy, method, args ->
            when (method.name) {
                "request" -> request
                "proceed" -> proceed(args!![0] as Request)
                "withConnectTimeout" -> proxy
                else -> error("Unexpected chain call: ${method.name}")
            }
        } as Interceptor.Chain

    private fun response(request: Request, code: Int): Response = Response.Builder()
        .request(request).protocol(Protocol.HTTP_2).code(code).message("fixture")
        .body("fixture".toResponseBody()).build()

    @Test fun directPolicyNeverUsesRelayers() {
        val requests = mutableListOf<Request>()
        val request = Request.Builder().url("https://vpn.mozilla.org/api/v1/fpn/token").build()
        val interceptor = FoxyRelayerInterceptor {
            FoxyRelayerConfig(RELAYER_DIRECT, "", setOf("guardian"), mapOf("test" to "https://relay.example"))
        }
        interceptor.intercept(chain(request) { requests.add(it); response(it, 451) }).use {
            assertEquals(451, it.code)
        }
        assertEquals(listOf(request), requests)
    }

    @Test fun invalidRelayerUrlsAreRejected() {
        assertTrue(isValidRelayerUrl("https://relay.example/path"))
        assertFalse(isValidRelayerUrl("http://relay.example"))
        assertFalse(isValidRelayerUrl("https://user:secret@relay.example"))
        assertFalse(isValidRelayerUrl("https://relay.example/#fragment"))
    }

    @Test fun unselectedCategoryStaysDirect() {
        val request = Request.Builder().url("https://example.org/health").build()
        val requests = mutableListOf<Request>()
        val interceptor = FoxyRelayerInterceptor {
            FoxyRelayerConfig(RELAYER_AUTOMATIC, "", emptySet(), mapOf("test" to "https://relay.example"))
        }
        interceptor.intercept(chain(request) { requests.add(it); response(it, 451) }).close()
        assertEquals(listOf(request), requests)
    }
}
