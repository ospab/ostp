package net.ostp.client

import androidx.annotation.Keep

@Keep
object OstpClientSdk {
    init {
        System.loadLibrary("ostp_jni")
    }

    @Keep
    @JvmStatic
    fun protectSocket(fd: Int): Boolean {
        var retries = 5
        while (retries > 0) {
            val service = com.ospab.ostp_client.OstpVpnService.instance
            if (service != null) {
                val res = service.protect(fd)
                android.util.Log.i("OstpClientSdk", "VpnService.protect(socketFd=$fd) -> success=$res")
                return res
            }
            android.util.Log.w("OstpClientSdk", "VpnService instance is null! Retrying... ($retries left)")
            Thread.sleep(200)
            retries--
        }
        android.util.Log.e("OstpClientSdk", "VpnService instance is null! Cannot protect socketFd=$fd")
        return false
    }

    @Keep
    @JvmStatic
    external fun startClient(configJson: String, fd: Int, t2sBinPath: String, localProxy: String): Boolean
    
    @Keep
    @JvmStatic
    external fun stopClient(): Boolean
    
    @Keep
    @JvmStatic
    external fun getMetrics(): String
    
    @Keep
    @JvmStatic
    external fun getLogs(): String
    
    @Keep
    @JvmStatic
    external fun addLog(logMsg: String)

    @Keep
    @JvmStatic
    external fun notifyNetworkChanged()

    @Keep
    @JvmStatic
    external fun runProberMatrix(requestJson: String): String

    @Keep
    @JvmStatic
    external fun runProberTtlScan(requestJson: String): String

    @Keep
    @JvmStatic
    external fun runProberDpiBattery(): String

    /**
     * Subscription document as JSON, or {"error": ...}. Blocking: call off the UI thread.
     * With [sendHwid] false the other three arguments are ignored and nothing about the
     * device is sent. With it true the core derives the per-server identifier from
     * [androidId] (the id itself is never sent) and sends [os] and [model] as text.
     * A non-empty [proxy] ("host:port" of the core's local SOCKS5 proxy) sends the request
     * through the tunnel; a failure is an error, never a retry outside the tunnel.
     */
    @Keep
    @JvmStatic
    external fun fetchSubscription(url: String, sendHwid: Boolean, androidId: String, os: String, model: String, proxy: String): String

    /** Release tag of this build, e.g. "v0.4.6-beta.2". */
    @Keep
    @JvmStatic
    external fun buildTag(): String

    /** Newer stable/beta releases as JSON, or {"error": ...}. Blocking: call off the UI thread. A non-empty [proxy] is as for [fetchSubscription]. */
    @Keep
    @JvmStatic
    external fun checkForUpdates(proxy: String): String

    /**
     * One request to the SSH server manager as JSON; `{"ok": ...}` or
     * `{"error": ...}`. Blocking (it can install a server): call off the UI thread.
     */
    @Keep
    @JvmStatic
    external fun serversCall(dataDir: String, masterKey: String, requestJson: String): String

    /**
     * Replaces the exclusions of the running client (JSON with `domains`,
     * `ips`, `processes`); false when no client runs or the JSON is invalid.
     */
    @Keep
    @JvmStatic
    external fun updateExclusions(json: String): Boolean

    /**
     * What the connected server said about itself inside the tunnel (JSON:
     * operator, server, key), or "" when it has not (yet).
     */
    @Keep
    @JvmStatic
    external fun getServerInfo(): String

    /**
     * Asks the connected server for its info again; false when no connected
     * server supports it. Read the answer with getServerInfo shortly after.
     */
    @Keep
    @JvmStatic
    external fun requestServerInfo(): Boolean
}
