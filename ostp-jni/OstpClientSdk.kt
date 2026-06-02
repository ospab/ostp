package net.ostp.client

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.*
import org.json.JSONArray
import org.json.JSONObject
import java.util.concurrent.atomic.AtomicBoolean

/**
 * OSTP Android Client SDK — Production-ready Kotlin wrapper for the native Rust OSTP VPN client.
 *
 * Usage:
 * ```kotlin
 * val sdk = OstpClientSdk.getInstance(context)
 * sdk.state.collect { state -> updateUi(state) }
 * sdk.start(OstpClientSdk.Config(server = "1.2.3.4:50000", accessKey = "your-key"))
 * ```
 *
 * The SDK:
 * - Loads the native `ostp_jni` shared library
 * - Exposes a reactive [StateFlow] of [TunnelState]
 * - Polls metrics and logs from the native layer at 1Hz
 * - Auto-reconnects on network changes via [ConnectivityManager]
 * - Cleans up gracefully on [stop]
 */
class OstpClientSdk private constructor(private val context: Context) {

    // ── Native JNI bindings ───────────────────────────────────────────────────

    private external fun startClient(configJson: String, fd: Int, t2sBinPath: String, localProxy: String): Boolean
    private external fun stopClient(): Boolean
    private external fun getMetrics(): String
    private external fun getLogs(): String
    private external fun addLog(logMsg: String)
    private external fun notifyNetworkChanged()


    // ── Public data models ────────────────────────────────────────────────────

    /**
     * Immutable configuration for the OSTP client session.
     *
     * @param server       OSTP server address in "host:port" format.
     * @param accessKey    Pre-shared access key hex string (generate with `./ostp -g`).
     * @param proxyBind    Local HTTP/SOCKS5 proxy bind address. Defaults to "127.0.0.1:1088".
     * @param mode         "proxy" (HTTP+SOCKS5 on [proxyBind]) or "tun" (full VPN, requires root/VpnService).
     * @param turnEnabled  Whether to route UDP via the Yandex TURN relay.
     * @param turnServer   TURN server address (e.g. "turn.yandex.net:3478").
     * @param turnUsername TURN credential username.
     * @param turnPassword TURN credential password/access key.
     * @param handshakeTimeoutMs Milliseconds to wait for server handshake response. Default 8000.
     */
    data class Config(
        val server: String,
        val accessKey: String,
        val proxyBind: String = "127.0.0.1:1088",
        val mode: String = "proxy",
        val turnEnabled: Boolean = false,
        val turnServer: String = "",
        val turnUsername: String = "",
        val turnPassword: String = "",
        val handshakeTimeoutMs: Long = 8000L,
    ) {
        init {
            require(server.isNotBlank()) { "server must not be blank" }
            require(accessKey.isNotBlank()) { "accessKey must not be blank" }
            require(mode == "proxy" || mode == "tun") { "mode must be 'proxy' or 'tun'" }
        }

        /** Serialises this config to the JSON format expected by the native layer. */
        fun toNativeJson(): String {
            return JSONObject().apply {
                put("mode", mode)
                put("debug", false)
                put("ostp", JSONObject().apply {
                    put("server_addr", server)
                    put("local_bind_addr", "0.0.0.0:0")
                    put("access_key", accessKey)
                    put("handshake_timeout_ms", handshakeTimeoutMs)
                    put("io_timeout_ms", 5000)
                })
                put("local_proxy", JSONObject().apply {
                    put("bind_addr", proxyBind)
                    put("connect_timeout_ms", 15000)
                })
                put("turn", JSONObject().apply {
                    put("enabled", turnEnabled)
                    put("server_addr", turnServer)
                    put("username", turnUsername)
                    put("access_key", turnPassword)
                })
                put("exclusions", JSONObject().apply {
                    put("domains", org.json.JSONArray())
                    put("ips", org.json.JSONArray())
                    put("processes", org.json.JSONArray())
                })
                put("multiplex", JSONObject().apply {
                    put("enabled", false)
                    put("sessions", 1)
                })
            }.toString()
        }
    }

    /** Live metrics snapshot from the active tunnel. */
    data class Metrics(
        val bytesSent: Long = 0L,
        val bytesRecv: Long = 0L,
        val rttMs: Double = 0.0,
    ) {
        val totalBytes: Long get() = bytesSent + bytesRecv
        val sentMb: Double get() = bytesSent / 1_000_000.0
        val recvMb: Double get() = bytesRecv / 1_000_000.0
    }

    /** Connection state machine for the tunnel. */
    sealed class TunnelState {
        /** No active tunnel, SDK is idle. */
        object Idle : TunnelState()

        /** Handshake in progress, waiting for server response. */
        object Connecting : TunnelState()

        /** Tunnel established and data is flowing. */
        data class Connected(val metrics: Metrics) : TunnelState()

        /** Tunnel dropped — will auto-reconnect unless [stop] was called. */
        data class Reconnecting(val reason: String, val attemptNumber: Int) : TunnelState()

        /** Terminal failure — [stop] was called or max reconnect attempts exceeded. */
        data class Failed(val reason: String) : TunnelState()
    }

    // ── State ─────────────────────────────────────────────────────────────────

    private val _state = MutableStateFlow<TunnelState>(TunnelState.Idle)

    /** Observe the current tunnel state. Safe to collect from any coroutine. */
    val state: StateFlow<TunnelState> = _state.asStateFlow()

    /** Whether the tunnel is currently active (Connected state). */
    val isConnected: Boolean get() = _state.value is TunnelState.Connected

    private val _logs = MutableSharedFlow<String>(extraBufferCapacity = 512)

    /** Observe log messages from the native layer in real-time. */
    val logs: SharedFlow<String> = _logs.asSharedFlow()

    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val started = AtomicBoolean(false)
    private var pollingJob: Job? = null
    private var networkCallbackJob: Job? = null
    private var currentConfig: Config? = null

    // ── Public API ────────────────────────────────────────────────────────────

    /**
     * Start the OSTP VPN tunnel with the given [config].
     *
     * This is idempotent: calling [start] while already connected is a no-op.
     * To change config, call [stop] first, then [start] with new config.
     *
     * @return `true` if the native layer accepted the start command.
     */
    fun start(config: Config): Boolean {
        if (started.getAndSet(true)) {
            emitLog("SDK already started; call stop() first to change config")
            return false
        }

        currentConfig = config
        _state.value = TunnelState.Connecting

        val json = config.toNativeJson()
        // Default values for fd, t2sBinPath, localProxy for proxy mode
        val ok = startClient(json, -1, "", config.proxyBind)
        if (!ok) {
            _state.value = TunnelState.Failed("Native layer rejected config")
            started.set(false)
            return false
        }

        startPolling()
        registerNetworkCallback(config)
        emitLog("OSTP SDK started → ${config.server} (mode=${config.mode})")
        return true
    }

    /**
     * Stop the tunnel and release all resources.
     * After this call the SDK transitions to [TunnelState.Idle] and can be [start]ed again.
     */
    fun stop() {
        if (!started.getAndSet(false)) return

        pollingJob?.cancel()
        networkCallbackJob?.cancel()
        stopClient()
        unregisterNetworkCallback()
        _state.value = TunnelState.Idle
        emitLog("OSTP SDK stopped")
    }

    /**
     * Read and drain all log lines produced by the native layer since the last call.
     * Prefer collecting [logs] SharedFlow for reactive usage.
     */
    fun drainLogs(): List<String> {
        return try {
            val array = JSONArray(getLogs())
            (0 until array.length()).map { array.getString(it) }
        } catch (_: Exception) {
            emptyList()
        }
    }

    /** Read the latest [Metrics] snapshot. Returns zeroed metrics if tunnel is idle. */
    fun getMetrics(): Metrics {
        return parseMetrics(getMetrics())
    }

    // ── Internal helpers ──────────────────────────────────────────────────────

    private fun startPolling() {
        pollingJob = scope.launch {
            var wasConnected = false
            while (isActive) {
                delay(1000L)

                // Drain and relay logs
                drainLogs().forEach { line ->
                    emitLog(line)
                    // Detect state transitions from log content
                    when {
                        line.contains("Connection established") ||
                        line.contains("TUN tunnel established") -> {
                            wasConnected = true
                        }
                        line.contains("Bridge stopped") ||
                        line.contains("TUN tunnel stopped") ||
                        line.contains("Connection failed") -> {
                            wasConnected = false
                        }
                    }
                }

                // Update state based on metrics availability
                val metrics = parseMetrics(getMetrics())
                if (wasConnected) {
                    _state.value = TunnelState.Connected(metrics)
                }
            }
        }
    }

    private fun registerNetworkCallback(config: Config) {
        networkCallbackJob = scope.launch {
            val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            val request = NetworkRequest.Builder()
                .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                .build()

            val callback = object : ConnectivityManager.NetworkCallback() {
                override fun onAvailable(network: Network) {
                    if (!started.get()) return
                    // Network became available (WiFi→LTE, tower switch, etc.)
                    // Send a lightweight BridgeCommand::NetworkChanged to Rust so the bridge
                    // immediately reconnects on the new interface without a full stop/start.
                    emitLog("Network available — signalling Rust bridge for immediate reconnect")
                    _state.value = TunnelState.Connecting
                    notifyNetworkChanged()
                }

                override fun onLost(network: Network) {
                    if (_state.value is TunnelState.Connected) {
                        _state.value = TunnelState.Reconnecting("Network lost", 0)
                        emitLog("Network lost — waiting for new network")
                    }
                }
            }

            try {
                cm.registerNetworkCallback(request, callback)
                awaitCancellation()
            } finally {
                runCatching { cm.unregisterNetworkCallback(callback) }
            }
        }
    }

    private fun unregisterNetworkCallback() {
        networkCallbackJob?.cancel()
    }

    private fun parseMetrics(json: String): Metrics {
        return try {
            val obj = JSONObject(json)
            Metrics(
                bytesSent = obj.optLong("bytes_sent", 0L),
                bytesRecv = obj.optLong("bytes_recv", 0L),
            )
        } catch (_: Exception) {
            Metrics()
        }
    }

    private fun emitLog(msg: String) {
        scope.launch { _logs.tryEmit(msg) }
    }

    // ── Singleton ─────────────────────────────────────────────────────────────

    companion object {
        init {
            System.loadLibrary("ostp_jni")
        }

        @Volatile
        private var instance: OstpClientSdk? = null

        @JvmStatic
        fun protectSocket(fd: Int): Boolean {
            var retries = 5
            while (retries > 0) {
                // We use reflection or explicit class to get the VpnService instance
                try {
                    val serviceClass = Class.forName("com.ospab.ostp_client.OstpVpnService")
                    val instanceField = serviceClass.getDeclaredField("instance")
                    instanceField.isAccessible = true
                    val service = instanceField.get(null)
                    if (service != null) {
                        val protectMethod = serviceClass.getMethod("protect", Int::class.javaPrimitiveType)
                        val res = protectMethod.invoke(service, fd) as Boolean
                        android.util.Log.i("OstpClientSdk", "VpnService.protect(socketFd=$fd) -> success=$res")
                        return res
                    }
                } catch (e: Exception) {
                    android.util.Log.w("OstpClientSdk", "Error accessing VpnService via reflection: \${e.message}")
                }
                android.util.Log.w("OstpClientSdk", "VpnService instance not available! Retrying... (\$retries left)")
                Thread.sleep(200)
                retries--
            }
            android.util.Log.e("OstpClientSdk", "VpnService instance is null! Cannot protect socketFd=\$fd")
            return false
        }

        /**
         * Get the singleton SDK instance.
         * Must be called with an Application context to avoid memory leaks.
         */
        fun getInstance(context: Context): OstpClientSdk {
            return instance ?: synchronized(this) {
                instance ?: OstpClientSdk(context.applicationContext).also { instance = it }
            }
        }
    }
}
