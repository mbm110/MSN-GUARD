package com.msnguard.vpn.foxy

import android.os.Build

import com.msnguard.vpn.foxy.FoxySettings
import io.netty.bootstrap.Bootstrap
import io.netty.buffer.ByteBuf
import io.netty.channel.Channel
import io.netty.channel.ChannelFuture
import io.netty.channel.ChannelHandlerContext
import io.netty.channel.ChannelInboundHandlerAdapter
import io.netty.channel.ChannelInitializer
import io.netty.channel.ChannelOption
import io.netty.channel.ChannelOutboundHandlerAdapter
import io.netty.channel.ChannelPromise
import io.netty.channel.SimpleChannelInboundHandler
import io.netty.channel.WriteBufferWaterMark
import io.netty.channel.nio.NioEventLoopGroup
import io.netty.handler.codec.http2.DefaultHttp2DataFrame
import io.netty.handler.codec.http2.DefaultHttp2Headers
import io.netty.handler.codec.http2.DefaultHttp2HeadersFrame
import io.netty.handler.codec.http2.DefaultHttp2PingFrame
import io.netty.handler.codec.http2.DefaultHttp2WindowUpdateFrame
import io.netty.handler.codec.http2.Http2CodecUtil
import io.netty.handler.codec.http2.Http2DataFrame
import io.netty.handler.codec.http2.Http2FrameCodecBuilder
import io.netty.handler.codec.http2.Http2FrameLogger
import io.netty.handler.codec.http2.Http2GoAwayFrame
import io.netty.handler.codec.http2.Http2HeadersFrame
import io.netty.handler.codec.http2.Http2MultiplexHandler
import io.netty.handler.codec.http2.Http2PingFrame
import io.netty.handler.codec.http2.Http2ResetFrame
import io.netty.handler.codec.http2.Http2Settings
import io.netty.handler.codec.http2.Http2SettingsFrame
import io.netty.handler.codec.http2.Http2StreamChannel
import io.netty.handler.codec.http2.Http2StreamChannelBootstrap
import io.netty.handler.codec.http2.Http2StreamFrame
import io.netty.handler.logging.LogLevel
import io.netty.handler.proxy.HttpProxyHandler
import io.netty.handler.proxy.ProxyHandler
import io.netty.handler.proxy.Socks5ProxyHandler
import io.netty.handler.ssl.ApplicationProtocolConfig
import io.netty.handler.ssl.ApplicationProtocolNames
import io.netty.resolver.NoopAddressResolverGroup
import io.netty.handler.ssl.SslContext
import io.netty.handler.ssl.SslContextBuilder
import io.netty.handler.ssl.SslHandshakeCompletionEvent
import io.netty.handler.ssl.SslProvider
import io.netty.handler.ssl.SupportedCipherSuiteFilter
import io.netty.util.ReferenceCountUtil
import io.netty.util.concurrent.Future
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import java.io.IOException
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.security.Provider
import java.security.Security
import java.util.concurrent.LinkedBlockingQueue
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

private const val TAG = "H2UpstreamSession"

private const val KEEPALIVE_CHECK_INTERVAL_MS = 3_000L
private const val KEEPALIVE_IDLE_THRESHOLD_MS = 15_000L
private const val KEEPALIVE_PING_TIMEOUT_MS = 25_000L

private const val KEEPALIVE_PING_PAYLOAD = 0x466F78795650_4EL

private const val OPEN_STREAM_TIMEOUT_MS = 20_000L

private const val TCP_CONNECT_TIMEOUT_MS = 15_000

private const val TLS_ENDPOINT_IDENTIFICATION_HTTPS = "HTTPS"

private const val CONSCRYPT_PROVIDER_NAME = "Conscrypt"

private val TLS_PROVIDER: Provider? = runCatching { Security.getProvider(CONSCRYPT_PROVIDER_NAME) }.getOrNull()

private val TLS_PROTOCOLS: Array<String> =
    if (TLS_PROVIDER != null || Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
        arrayOf("TLSv1.3", "TLSv1.2")
    } else {
        arrayOf("TLSv1.2")
    }

private const val HTTP2_FLOW_CONTROL_WINDOW_BYTES = 16 * 1024 * 1024

private const val HTTP2_MAX_FRAME_SIZE_BYTES = 256 * 1024

private val STREAM_WRITE_WATER_MARK = WriteBufferWaterMark(512 * 1024, 2 * 1024 * 1024)

private val PARENT_WRITE_WATER_MARK = WriteBufferWaterMark(1024 * 1024, 4 * 1024 * 1024)

private const val WRITE_BACKPRESSURE_TIMEOUT_MS = 60_000L

private const val STREAM_SLOT_WAIT_TIMEOUT_MS = 15_000L

private const val STREAM_SLOT_POLL_INTERVAL_MS = 20L

private const val DRAIN_IDLE_TIMEOUT_MS = 120_000L

private const val DRAIN_POLL_INTERVAL_MS = 250L

data class UpstreamProxyConfig(
    val type: Type,
    val host: String,
    val port: Int,
    val username: String? = null,
    val password: String? = null,
) {
    enum class Type { SOCKS5, HTTP }
}

class H2UpstreamSession(
    private val upstreamHost: String,
    private val upstreamPort: Int,
    bearerToken: String,
    private val upstreamProxy: UpstreamProxyConfig? = null,
    private val edgeAddress: String? = null,
    private val tlsSplitMode: FoxySettings.TlsSplitMode = FoxySettings.TlsSplitMode.OFF,
    /** Foxy-only local cap; peer SETTINGS can reduce it further. */
    private val localMaxConcurrentStreams: Int = 8,
) : UpstreamSession {

    private val group = NioEventLoopGroup(1)

    @Volatile private var currentBearerToken: String = bearerToken

    private val connectHost: String = edgeAddress?.takeIf { it.isNotBlank() } ?: upstreamHost

    private val keepaliveScope = CoroutineScope(SupervisorJob() + Dispatchers.Default)
    private var parentChannel: Channel? = null

    @Volatile private var lastActivityAt = System.currentTimeMillis()

    @Volatile private var lastStreamDataAt = System.currentTimeMillis()
    @Volatile private var awaitingPingAck = false
    @Volatile private var pingSentAt = 0L
    @Volatile private var acceptingNewStreams = true
    private val activeStreams = AtomicInteger(0)

    @Volatile private var maxConcurrentStreams = localMaxConcurrentStreams.coerceIn(1, 64)

    private val closed = AtomicBoolean(false)

    @Volatile private var closing = false

    private val drainWatcherArmed = AtomicBoolean(false)

    override val isConnected: Boolean
        get() = parentChannel?.isActive == true && acceptingNewStreams

    override fun updateBearerToken(token: String) {
        if (token.isBlank() || token == currentBearerToken) return
        currentBearerToken = token
        FoxyLog.i(
            TAG,
            "proxy pass swapped into the live session; the existing HTTP/2 tunnel keeps running and " +
                "subsequent flows authenticate with the new pass",
        )
    }

    override fun disableNewStreamsAndCloseWhenIdle() {
        acceptingNewStreams = false
        if (activeStreams.get() == 0) {
            close()
            return
        }

        if (!drainWatcherArmed.compareAndSet(false, true)) return

        lastStreamDataAt = System.currentTimeMillis()
        keepaliveScope.launch {

            while (activeStreams.get() > 0 &&
                System.currentTimeMillis() - lastStreamDataAt < DRAIN_IDLE_TIMEOUT_MS
            ) {
                delay(DRAIN_POLL_INTERVAL_MS)
            }
            val stranded = activeStreams.get()
            if (stranded > 0) {
                FoxyLog.w(
                    TAG,
                    "a swapped-out upstream session has moved no data for " +
                        "${DRAIN_IDLE_TIMEOUT_MS / 1_000}s with $stranded flow(s) still open; closing it so its " +
                        "socket and event loop are not held for the lifetime of the tunnel",
                )
            }
            close()
        }
    }

    private fun noteInboundActivity() {
        lastActivityAt = System.currentTimeMillis()
        if (awaitingPingAck) awaitingPingAck = false
    }

    private fun noteStreamData() {
        val now = System.currentTimeMillis()
        lastActivityAt = now

        lastStreamDataAt = now
    }

    override suspend fun connect() = withContext(Dispatchers.IO) {

        val sslContextBuilder = SslContextBuilder.forClient()
            .sslProvider(SslProvider.JDK)
            .protocols(*TLS_PROTOCOLS)
            .applicationProtocolConfig(
                ApplicationProtocolConfig(
                    ApplicationProtocolConfig.Protocol.ALPN,

                    ApplicationProtocolConfig.SelectorFailureBehavior.FATAL_ALERT,
                    ApplicationProtocolConfig.SelectedListenerFailureBehavior.FATAL_ALERT,
                    ApplicationProtocolNames.HTTP_2,
                ),
            )
            .ciphers(null, SupportedCipherSuiteFilter.INSTANCE)

        val tlsProvider = TLS_PROVIDER
        if (tlsProvider != null) {
            sslContextBuilder.sslContextProvider(tlsProvider)
        } else {
            FoxyLog.w(
                TAG,
                "Conscrypt is unavailable; falling back to the platform TLS stack " +
                    "(protocols=${TLS_PROTOCOLS.joinToString()})",
            )
        }

        UpstreamTrust.trustManagerFactory()?.let { sslContextBuilder.trustManager(it) }
        val sslContext: SslContext = sslContextBuilder.build()

        if (connectHost != upstreamHost) {
            FoxyLog.i(
                TAG,
                "custom edge address in use: TCP to $connectHost:$upstreamPort, still presenting and " +
                    "verifying \"$upstreamHost\"",
            )
        }

        val handshakeDone = CompletableDeferred<Unit>()
        val bootstrap = Bootstrap()
            .group(group)
            .channel(FoxyNioSocketChannel::class.java)
            .apply {
                if (upstreamProxy != null) resolver(NoopAddressResolverGroup.INSTANCE)
            }

            .option(ChannelOption.TCP_NODELAY, true)

            .option(ChannelOption.SO_KEEPALIVE, true)
            .option(ChannelOption.CONNECT_TIMEOUT_MILLIS, TCP_CONNECT_TIMEOUT_MS)
            .option(ChannelOption.WRITE_BUFFER_WATER_MARK, PARENT_WRITE_WATER_MARK)
            .handler(object : ChannelInitializer<FoxyNioSocketChannel>() {
                override fun initChannel(ch: FoxyNioSocketChannel) {
                    runCatching {
                        FoxyControlPlaneHttp.socketProtector?.invoke(ch.publicJavaChannel().socket())
                    }.onFailure {
                        FoxyLog.e(TAG, "failed to protect netty socket", it)
                    }

                    upstreamProxy?.let { proxy -> ch.pipeline().addLast(buildProxyHandler(proxy)) }

                    if (tlsSplitMode != FoxySettings.TlsSplitMode.OFF) {
                        ch.pipeline().addLast("tlsSplit", TlsSplitHandler(tlsSplitMode))
                    }

                    val sslHandler = sslContext.newHandler(ch.alloc(), upstreamHost, upstreamPort)

                    val engine = sslHandler.engine()
                    engine.sslParameters = engine.sslParameters.apply {
                        endpointIdentificationAlgorithm = TLS_ENDPOINT_IDENTIFICATION_HTTPS
                    }

                    val frameCodecBuilder = Http2FrameCodecBuilder.forClient()

                        .initialSettings(
                            Http2Settings.defaultSettings()
                                .initialWindowSize(HTTP2_FLOW_CONTROL_WINDOW_BYTES)
                                .maxFrameSize(HTTP2_MAX_FRAME_SIZE_BYTES)
                                .pushEnabled(false),
                        )

                        .autoAckPingFrame(false)
                    if (false) {

                        frameCodecBuilder.frameLogger(Http2FrameLogger(LogLevel.DEBUG))
                    }
                    val frameCodec = frameCodecBuilder.build()
                    ch.pipeline().addLast(sslHandler)
                    ch.pipeline().addLast(frameCodec)

                    ch.pipeline().addLast(Http2MultiplexHandler(RejectPushStreamHandler()))

                    ch.pipeline().addLast(object : ChannelInboundHandlerAdapter() {
                        override fun channelRead(ctx: ChannelHandlerContext, msg: Any) {
                            noteInboundActivity()
                            when (msg) {
                                is Http2GoAwayFrame -> {
                                    acceptingNewStreams = false
                                    val reason = msg.content().toString(Charsets.UTF_8).ifBlank { "<no reason given>" }
                                    FoxyLog.w(
                                        TAG,
                                        "upstream sent GOAWAY: errorCode=${msg.errorCode()} lastStreamId=${msg.lastStreamId()} reason=\"$reason\"",
                                    )
                                    msg.release()
                                }
                                is Http2SettingsFrame -> {

                                    val announced = msg.settings().maxConcurrentStreams()
                                    if (announced != null) {

                                        val limit = announced.coerceIn(1L, localMaxConcurrentStreams.coerceIn(1, 64).toLong()).toInt()
                                        if (limit != maxConcurrentStreams) {
                                            maxConcurrentStreams = limit
                                            FoxyLog.i(
                                                TAG,
                                                "upstream allows $limit concurrent stream(s); new flows will wait " +
                                                    "for a free slot instead of being refused",
                                            )
                                        }
                                    }
                                }
                                is Http2PingFrame -> {

                                    if (msg.ack()) {
                                        if (msg.content() == KEEPALIVE_PING_PAYLOAD) awaitingPingAck = false
                                    } else {
                                        ctx.writeAndFlush(DefaultHttp2PingFrame(msg.content(), true))
                                    }
                                }
                                else -> {

                                    ReferenceCountUtil.release(msg)
                                }
                            }
                        }

                        override fun channelInactive(ctx: ChannelHandlerContext) {
                            acceptingNewStreams = false
                            val detail = "upstream channel to $upstreamHost:$upstreamPort became inactive " +
                                "(local=${ctx.channel().localAddress()})"

                            if (closing) FoxyLog.d(TAG, detail) else FoxyLog.w(TAG, detail)
                            if (!handshakeDone.isCompleted) {
                                handshakeDone.completeExceptionally(
                                    IOException("Upstream connection closed before completing the TLS/ALPN handshake"),
                                )
                            }
                            super.channelInactive(ctx)
                        }

                        override fun exceptionCaught(ctx: ChannelHandlerContext, cause: Throwable) {

                            if (closing || handshakeDone.isCompleted) {

                                FoxyLog.w(
                                    TAG,
                                    "upstream connection to $upstreamHost:$upstreamPort dropped: ${cause.message} " +
                                        "(usually the network changed underneath it)",
                                )
                            } else {
                                FoxyLog.e(
                                    TAG,
                                    "upstream channel error to $upstreamHost:$upstreamPort (often a TLS/ALPN handshake or, " +
                                        "if an upstream proxy is configured, a proxy CONNECT failure)",
                                    cause,
                                )
                            }
                            if (!handshakeDone.isCompleted) handshakeDone.completeExceptionally(cause)
                            ctx.close()
                        }

                        override fun userEventTriggered(ctx: ChannelHandlerContext, evt: Any) {
                            if (evt is SslHandshakeCompletionEvent) {
                                if (evt.isSuccess) {
                                    val negotiated = sslHandler.applicationProtocol()
                                    FoxyLog.i(
                                        TAG,
                                        "TLS handshake to $connectHost:$upstreamPort complete, " +
                                            "verified name=$upstreamHost, negotiated ALPN protocol=$negotiated, " +
                                            "local=${ctx.channel().localAddress()}",
                                    )
                                    if (negotiated == ApplicationProtocolNames.HTTP_2) {
                                        handshakeDone.complete(Unit)
                                    } else {
                                        val err = IllegalStateException(
                                            "Upstream did not negotiate HTTP/2 over ALPN (got '$negotiated')",
                                        )
                                        handshakeDone.completeExceptionally(err)
                                        ctx.close()
                                    }
                                } else {
                                    val cause = evt.cause() ?: IllegalStateException("TLS handshake failed with no cause")
                                    FoxyLog.e(TAG, "TLS/ALPN handshake to $connectHost:$upstreamPort failed", cause)
                                    handshakeDone.completeExceptionally(cause)
                                }
                            }
                            super.userEventTriggered(ctx, evt)
                        }
                    })
                }
            })

        parentChannel = if (upstreamProxy != null) {
            bootstrap.connect(InetSocketAddress.createUnresolved(connectHost, upstreamPort)).awaitChannel()
        } else {
            bootstrap.connect(connectHost, upstreamPort).awaitChannel()
        }
        handshakeDone.await()
        lastActivityAt = System.currentTimeMillis()
        lastStreamDataAt = System.currentTimeMillis()

        parentChannel?.writeAndFlush(
            DefaultHttp2WindowUpdateFrame(HTTP2_FLOW_CONTROL_WINDOW_BYTES - Http2CodecUtil.DEFAULT_WINDOW_SIZE),
        )
        startKeepalive()
    }

    private fun buildProxyHandler(proxy: UpstreamProxyConfig): ProxyHandler {
        val proxyAddress = InetSocketAddress(proxy.host, proxy.port)
        val hasCredentials = !proxy.username.isNullOrBlank()
        FoxyLog.i(
            TAG,
            "chaining upstream connection to $connectHost:$upstreamPort through ${proxy.type} proxy $proxyAddress",
        )
        return when (proxy.type) {
            UpstreamProxyConfig.Type.SOCKS5 -> if (hasCredentials) {
                Socks5ProxyHandler(proxyAddress, proxy.username, proxy.password.orEmpty())
            } else {
                Socks5ProxyHandler(proxyAddress)
            }
            UpstreamProxyConfig.Type.HTTP -> if (hasCredentials) {
                HttpProxyHandler(proxyAddress, proxy.username, proxy.password.orEmpty())
            } else {
                HttpProxyHandler(proxyAddress)
            }
        }
    }

    private fun startKeepalive() {
        keepaliveScope.launch {

            while (isActive && parentChannel?.isActive == true && !closed.get()) {
                delay(KEEPALIVE_CHECK_INTERVAL_MS)
                val now = System.currentTimeMillis()
                val idleFor = now - lastActivityAt
                val ch = parentChannel ?: break
                when {

                    awaitingPingAck && now - pingSentAt >= KEEPALIVE_PING_TIMEOUT_MS -> {
                        FoxyLog.w(
                            TAG,
                            "keepalive PING went unanswered for ${now - pingSentAt}ms; closing dead upstream session",
                        )
                        close()
                        break
                    }
                    !awaitingPingAck && idleFor >= KEEPALIVE_IDLE_THRESHOLD_MS -> {
                        awaitingPingAck = true
                        pingSentAt = now
                        ch.writeAndFlush(DefaultHttp2PingFrame(KEEPALIVE_PING_PAYLOAD, false))
                    }
                }
            }
        }
    }

    private fun releaseStreamSlot() {
        if (activeStreams.decrementAndGet() == 0 && !acceptingNewStreams) {
            close()
        }
    }

    private fun tryReserveStreamSlot(): Boolean {
        while (true) {
            val inFlight = activeStreams.get()
            if (inFlight >= maxConcurrentStreams) return false

            if (activeStreams.compareAndSet(inFlight, inFlight + 1)) return true
        }
    }

    private suspend fun reserveStreamSlot(authority: String) {
        if (tryReserveStreamSlot()) return

        val acquired = withTimeoutOrNull(STREAM_SLOT_WAIT_TIMEOUT_MS) {
            while (!tryReserveStreamSlot()) {
                if (!isConnected) {
                    throw IOException("H2UpstreamSession closed while waiting for a free stream slot")
                }
                delay(STREAM_SLOT_POLL_INTERVAL_MS)
            }
            true
        }
        if (acquired == null) {
            throw UpstreamConnectTimeoutException(
                authority = authority,
                message = "Timed out waiting for one of the upstream's $maxConcurrentStreams concurrent " +
                    "stream slots to free up",
                cause = IOException("upstream concurrent stream limit reached"),
            )
        }
    }

    override suspend fun openStream(targetHost: String, targetPort: Int): TunneledStream {

        val parent = parentChannel ?: throw IOException("H2UpstreamSession is not connected")
        if (!parent.isActive) throw IOException("H2UpstreamSession channel is not active")
        if (!acceptingNewStreams) throw IOException("H2UpstreamSession is shutting down (GOAWAY received)")

        val authority = if (targetHost.contains(":")) "[$targetHost]:$targetPort" else "$targetHost:$targetPort"
        val responseHeaders = CompletableDeferred<Unit>()
        val streamInput = NettyStreamInput()

        reserveStreamSlot(authority)

        var handedOff = false
        try {
            val streamChannel = run {
                val streamChannelFuture = Http2StreamChannelBootstrap(parent)

                    .option(ChannelOption.WRITE_BUFFER_WATER_MARK, STREAM_WRITE_WATER_MARK)
                    .handler(object : SimpleChannelInboundHandler<Http2StreamFrame>() {
                        override fun channelActive(ctx: ChannelHandlerContext) {
                            streamInput.attachChannel(ctx.channel() as Http2StreamChannel)
                            super.channelActive(ctx)
                        }

                        override fun channelRead0(ctx: ChannelHandlerContext, frame: Http2StreamFrame) {
                            noteInboundActivity()
                            when (frame) {
                                is Http2HeadersFrame -> {

                                    val statusText = frame.headers().status()?.toString()

                                    val statusCode = statusText?.trim()?.toIntOrNull()
                                    if (statusCode != null && statusCode in 200..299) {
                                        if (!responseHeaders.isCompleted) responseHeaders.complete(Unit)
                                    } else {
                                        val cause = UpstreamConnectRejectedException(
                                            statusCode = statusCode,
                                            authority = authority,
                                            message = "Upstream rejected CONNECT to $authority: status=${statusText ?: "<missing>"}",
                                        )
                                        if (!responseHeaders.isCompleted) responseHeaders.completeExceptionally(cause)
                                        ctx.close()
                                    }
                                }
                                is Http2DataFrame -> {

                                    noteStreamData()
                                    val bytes = ByteArray(frame.content().readableBytes())
                                    frame.content().readBytes(bytes)
                                    streamInput.offerData(bytes)
                                    if (frame.isEndStream) streamInput.offerEnd()
                                }
                                is Http2ResetFrame -> {
                                    val streamId = (ctx.channel() as Http2StreamChannel).stream().id()
                                    val cause = IOException("Upstream reset stream $streamId (errorCode=${frame.errorCode()})")
                                    FoxyLog.d(TAG, "upstream reset stream $streamId: errorCode=${frame.errorCode()}")
                                    if (!responseHeaders.isCompleted) responseHeaders.completeExceptionally(cause)
                                    streamInput.offerError(cause)
                                }
                                else -> Unit
                            }
                        }

                        override fun channelInactive(ctx: ChannelHandlerContext) {

                            if (!responseHeaders.isCompleted) {
                                responseHeaders.completeExceptionally(
                                    IOException("Upstream stream closed before CONNECT completed"),
                                )
                            }
                            streamInput.offerEnd()
                            super.channelInactive(ctx)
                        }
                    })
                    .open()

                val ch = try {
                    withTimeout(OPEN_STREAM_TIMEOUT_MS) { awaitStreamChannel(streamChannelFuture) }
                } catch (e: TimeoutCancellationException) {

                    throw UpstreamConnectTimeoutException(
                        authority = authority,
                        message = "Timed out opening HTTP/2 stream channel to $upstreamHost:$upstreamPort",
                        cause = e,
                    )
                }

                val headers = DefaultHttp2Headers().apply {
                    method("CONNECT")
                    authority(authority)

                    add("proxy-authorization", "Bearer $currentBearerToken")
                }
                ch.writeAndFlush(DefaultHttp2HeadersFrame(headers, false))

                try {
                    withTimeout(OPEN_STREAM_TIMEOUT_MS) { responseHeaders.await() }
                } catch (e: TimeoutCancellationException) {
                    ch.close()
                    throw UpstreamConnectTimeoutException(
                        authority = authority,
                        message = "Timed out waiting for CONNECT response from $upstreamHost:$upstreamPort ($authority)",
                        cause = e,
                    )
                }

                ch
            }

            streamChannel.closeFuture().addListener {
                releaseStreamSlot()
            }
            handedOff = true

            // Byte counting lives inside NettyStreamInput/NettyStreamOutput (below).
            // The counters used to ride java.io.Filter{Input,Output}Stream
            // wrappers here, and FilterOutputStream.write(byte[], off, len)
            // is BYTE-BY-BYTE: our override write(Int) → write(ByteArray) →
            // write(ByteArray, off, len) → super.write → write(Int) again —
            // infinite recursion, StackOverflowError on the FIRST client byte
            // relayed. That is exactly the alpha38 death "pb: <hash> —
            // connection closed". The reference project returns the raw
            // streams with no wrappers; these counters are MSN's traffic-tile
            // counters only, so they move into the netty stream classes.
            return TunneledStream(
                input = streamInput,
                output = NettyStreamOutput(streamChannel),
                close = { streamChannel.close() },
            )
        } finally {

            if (!handedOff) releaseStreamSlot()
        }
    }

    override fun close() {

        if (!closed.compareAndSet(false, true)) return
        closing = true
        keepaliveScope.cancel()
        parentChannel?.close()

        group.shutdownGracefully(0, 1, TimeUnit.SECONDS)
    }

    private class RejectPushStreamHandler : ChannelInitializer<Http2StreamChannel>() {
        override fun initChannel(ch: Http2StreamChannel) {
            FoxyLog.w(TAG, "upstream opened an unexpected server-initiated stream ${ch.stream().id()}; closing it")
            ch.close()
        }
    }

    private inner class NettyStreamOutput(
        private val streamChannel: Http2StreamChannel,
    ) : OutputStream() {
        override fun write(b: Int) = write(byteArrayOf(b.toByte()))

        override fun write(b: ByteArray, off: Int, len: Int) {
            if (len <= 0) return
            if (!streamChannel.isActive) throw IOException("Upstream stream is closed")

            noteStreamData()
            val buf = streamChannel.alloc().buffer(len).writeBytes(b, off, len)
            val future = streamChannel.writeAndFlush(DefaultHttp2DataFrame(buf, false))

            if (!streamChannel.isWritable) {
                if (!future.await(WRITE_BACKPRESSURE_TIMEOUT_MS, TimeUnit.MILLISECONDS)) {
                    future.cancel(false)
                    throw IOException("Upstream stream stopped accepting data (write timed out)")
                }
                if (!future.isSuccess) {
                    throw IOException("Failed writing to the upstream stream", future.cause())
                }
            } else if (future.isDone && !future.isSuccess) {

                throw IOException("Failed writing to the upstream stream", future.cause())
            }

            // Traffic-tile counter. Counted once per bulk write here — NOT on a
            // FilterOutputStream wrapper (see openStream(): that recursion
            // died with a StackOverflowError on the first relayed byte).
            FoxyTunnel.txBytes += len
        }

        override fun close() {

            if (streamChannel.isActive) streamChannel.writeAndFlush(DefaultHttp2DataFrame(true))
        }
    }

    private class NettyStreamInput : InputStream() {
        private sealed class Chunk {
            class Data(val bytes: ByteArray) : Chunk()
            object End : Chunk()
            class Error(val cause: Throwable) : Chunk()
        }

        private val queue = LinkedBlockingQueue<Chunk>()
        private val pendingBytes = AtomicInteger(0)
        private var current: ByteArray? = null
        private var currentPos = 0

        private var pendingTerminal: Chunk? = null
        @Volatile private var finished = false
        @Volatile private var channel: Http2StreamChannel? = null

        fun attachChannel(ch: Http2StreamChannel) {
            channel = ch
        }

        fun offerData(bytes: ByteArray) {
            if (bytes.isEmpty()) return
            queue.put(Chunk.Data(bytes))
            if (pendingBytes.addAndGet(bytes.size) >= HIGH_WATERMARK_BYTES) {
                channel?.config()?.isAutoRead = false
            }
        }

        fun offerEnd() = queue.put(Chunk.End)

        fun offerError(cause: Throwable) = queue.put(Chunk.Error(cause))

        override fun read(): Int {
            val single = ByteArray(1)
            val n = read(single, 0, 1)
            return if (n <= 0) -1 else single[0].toInt() and 0xFF
        }

        override fun read(b: ByteArray, off: Int, len: Int): Int {
            val n = readInner(b, off, len)
            if (n > 0) FoxyTunnel.rxBytes += n
            return n
        }

        /** Actual pump; [read] counts exactly one increment per byte (no FilterInputStream wrapper — see openStream()). */
        private fun readInner(b: ByteArray, off: Int, len: Int): Int {
            if (len == 0) return 0
            if (finished && current == null) return -1
            var totalRead = 0
            while (totalRead < len) {
                if (current == null || currentPos >= current!!.size) {
                    val chunk = pendingTerminal?.also { pendingTerminal = null }
                        ?: if (totalRead == 0) queue.take() else (queue.poll() ?: break)
                    when (chunk) {
                        is Chunk.Data -> {
                            current = chunk.bytes
                            currentPos = 0
                            val remaining = pendingBytes.addAndGet(-chunk.bytes.size)
                            val ch = channel
                            if (ch != null && remaining <= LOW_WATERMARK_BYTES) {
                                ch.eventLoop().execute { ch.config().isAutoRead = true }
                            }
                        }
                        is Chunk.End -> {
                            if (totalRead > 0) {

                                pendingTerminal = Chunk.End
                                return totalRead
                            }
                            finished = true
                            return -1
                        }
                        is Chunk.Error -> {
                            if (totalRead > 0) {
                                pendingTerminal = chunk
                                return totalRead
                            }
                            finished = true
                            throw IOException("Upstream stream failed", chunk.cause)
                        }
                    }
                }
                val data = current ?: break
                val available = data.size - currentPos
                val toCopy = minOf(len - totalRead, available)
                System.arraycopy(data, currentPos, b, off + totalRead, toCopy)
                currentPos += toCopy
                totalRead += toCopy
                if (currentPos >= data.size) current = null
            }
            return totalRead
        }

        companion object {

            private const val HIGH_WATERMARK_BYTES = 128 * 1024
            private const val LOW_WATERMARK_BYTES = 32 * 1024
        }
    }
}

private suspend fun awaitStreamChannel(future: Future<Http2StreamChannel>): Http2StreamChannel =
    suspendCancellableCoroutine { cont ->
        future.addListener {
            if (future.isSuccess) {
                cont.resume(future.now)
            } else {
                cont.resumeWithException(future.cause() ?: IllegalStateException("Netty future failed with no cause"))
            }
        }
        cont.invokeOnCancellation { future.cancel(false) }
    }

private suspend fun ChannelFuture.awaitChannel(): Channel =
    suspendCancellableCoroutine { cont ->
        addListener { completed ->
            if (completed.isSuccess) {
                cont.resume(channel())
            } else {
                cont.resumeWithException(
                    completed.cause() ?: IOException("Upstream TCP connect failed with no cause"),
                )
            }
        }
        cont.invokeOnCancellation {
            runCatching { channel().close() }
        }
    }

@androidx.annotation.Keep
internal class FoxyNioSocketChannel : io.netty.channel.socket.nio.NioSocketChannel() {
    fun publicJavaChannel(): java.nio.channels.SocketChannel = super.javaChannel() as java.nio.channels.SocketChannel
}

private class TlsSplitHandler(
    private val mode: FoxySettings.TlsSplitMode,
) : ChannelOutboundHandlerAdapter() {
    private var splitDone = false

    override fun write(
        ctx: ChannelHandlerContext,
        msg: Any,
        promise: ChannelPromise,
    ) {
        if (splitDone || msg !is ByteBuf) {
            super.write(ctx, msg, promise)
            return
        }

        if (!TlsClientHelloSplitter.looksLikeClientHello(msg)) {
            super.write(ctx, msg, promise)
            return
        }

        splitDone = true
        val segments = try {
            TlsClientHelloSplitter.split(msg, mode)
        } catch (e: Throwable) {
            FoxyLog.w(TAG, "failed to split TLS ClientHello, falling back to direct write", e)
            null
        }

        if (segments.isNullOrEmpty()) {
            super.write(ctx, msg, promise)
            return
        }

        FoxyLog.i(TAG, "TLS ClientHello fragmented ($mode) into ${segments.size} TCP segment(s)")
        val total = segments.size
        for (i in segments.indices) {
            val seg = segments[i]
            if (i == total - 1) {
                ctx.writeAndFlush(seg, promise)
            } else {
                val subPromise = ctx.newPromise()
                subPromise.addListener { f ->
                    if (!f.isSuccess) {
                        promise.tryFailure(f.cause())
                    }
                }
                ctx.writeAndFlush(seg, subPromise)
            }
        }
        ReferenceCountUtil.release(msg)
    }
}

