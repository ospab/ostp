package com.ospab.ostp_client

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.os.PowerManager
import android.util.Log
import net.ostp.client.OstpClientSdk
import java.io.IOException
import androidx.annotation.Keep
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.app.ServiceCompat

@Keep
class OstpVpnService : VpnService() {

    @Keep
    companion object {
        @Keep
        @Volatile
        var isRunning = false
        // Between a START and the core being up (or failing): the tile shows it as connecting.
        @Volatile
        var isStarting = false
        // The core's local SOCKS5 proxy ("host:port") while it runs, else empty. The app's own
        // requests (subscriptions, update checks) go through it when the person wants that.
        @Volatile
        var localProxyAddr = ""
        // The core's connection_state while the tunnel runs (0 none, 1 handshake or
        // reconnect, 2 connected to the server); 0 when no tunnel runs.
        @Volatile
        var linkState = 0
        @Keep
        var instance: OstpVpnService? = null
        // Bumped on every start; a service instance may tear down only the tunnel it owns.
        @Volatile
        private var generation = 0

        private const val NOTIF_ID = 1001
        private const val CHANNEL_ID = "ostp_vpn_channel"
        private const val WAKE_LOCK_TAG = "ostp:vpn_wakelock"

        // How long the core may report "not connected" before the service ends the
        // tunnel. The app, when it is open, polls every second and stops sooner with
        // the reason the server gave; these limits only matter when nothing else
        // watches (the tunnel was started from the tile, or the app was closed).
        const val CORE_GONE_AFTER_UP_MS = 5_000L
        const val CORE_SILENT_AT_START_MS = 25_000L

        /**
         * True when the core has stopped for good: it was connected (or
         * connecting) and has reported 0 for [CORE_GONE_AFTER_UP_MS], or it never
         * reported anything in [CORE_SILENT_AT_START_MS] after the start. The
         * core reconnects on its own and reports 1 meanwhile, so a reconnect is
         * never taken for a stop.
         */
        fun coreGone(everUp: Boolean, zeroForMs: Long, sinceStartMs: Long): Boolean =
            if (everUp) zeroForMs >= CORE_GONE_AFTER_UP_MS else sinceStartMs >= CORE_SILENT_AT_START_MS
    }

    // Reads the core's state off the main thread (the JNI call takes the core's lock).
    private var watcher: java.util.concurrent.ScheduledExecutorService? = null
    // Main-thread only: what the watcher has seen of the current tunnel.
    private var watchStartedAt = 0L
    private var coreEverUp = false
    private var zeroSince = 0L

    // The generation of the tunnel this instance started (0 = none).
    private var ownedGeneration = 0
    // The profile being connected, for the notification; null when the app saved none.
    private var profileName: String? = null
    private var vpnInterface: ParcelFileDescriptor? = null
    private var wakeLock: PowerManager.WakeLock? = null
    private var networkCallback: android.net.ConnectivityManager.NetworkCallback? = null
    private val mainHandler = android.os.Handler(android.os.Looper.getMainLooper())
    // The physical network the tunnel currently runs over. Only touched on the main thread.
    private var currentNetwork: android.net.Network? = null
    private var currentAddresses: Set<java.net.InetAddress> = emptySet()
    private val notifyRust = Runnable {
        Log.i("OstpVpnService", "Default network changed, signalling the core")
        OstpClientSdk.notifyNetworkChanged()
    }

    override fun onCreate() {
        super.onCreate()
        instance = this
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val action = intent?.action
        if (action == "START") {
            // A service started with startForegroundService must call startForeground
            // soon even if it then has nothing to run, or the system kills the app.
            isStarting = true
            if (!isRunning) linkState = 0
            OstpTileService.refresh()
            startForegroundSafe()
            val configJson = intent.getStringExtra("configJson")
            if (configJson == null) {
                stopVpn()
                return START_NOT_STICKY
            }
            synchronized(OstpVpnService::class.java) {
                ownedGeneration = ++generation
                instance = this
            }
            startVpn(configJson)
        } else if (action == "STOP") {
            stopVpn()
        } else if (!isRunning) {
            // A restart by the system after the process died (null intent) or a bind by
            // always-on VPN: there is no tunnel, and a service idling without one only
            // pretends to be a VPN. Stop; the user connects from the app.
            stopSelf()
        }
        // Not sticky: after the process is killed the tunnel is gone and is not brought
        // back behind the user's back.
        return START_NOT_STICKY
    }

    /**
     * The type passed here must be one declared on the service in the manifest
     * (connectedDevice). Its runtime prerequisite on Android 14+ is met by the
     * declared CHANGE_NETWORK_STATE permission ("Foreground service types",
     * Connected device). ServiceCompat drops the type below API 29.
     *
     * Without POST_NOTIFICATIONS (Android 13+, a runtime permission the app does
     * not ask for) the service still runs in the foreground; the system only
     * hides this notification from the shade and lists the app in its task manager.
     */
    private fun startForegroundSafe() {
        try {
            ServiceCompat.startForeground(this, NOTIF_ID, buildNotification(connecting = linkState != 2), ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE)
        } catch (e: Throwable) {
            // Blocked notifications (Android 13+) do not prevent the foreground state;
            // anything else is logged and the tunnel still tries to start.
            Log.e("OstpVpnService", "startForeground failed", e)
        }
    }

    /** Another VPN app took over, or the permission was revoked in system settings. */
    override fun onRevoke() {
        Log.w("OstpVpnService", "VPN permission revoked")
        try {
            OstpClientSdk.addLog("The VPN was taken over by another app or its permission was revoked")
        } catch (_: Throwable) {}
        stopVpn()
        super.onRevoke()
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "OSTP VPN",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "VPN connection status"
                setShowBadge(false)
                setSound(null, null)
                enableVibration(false)
                enableLights(false)
            }
            val nm = getSystemService(NotificationManager::class.java)
            nm.createNotificationChannel(channel)
        }
    }

    /**
     * One quiet line: the profile and the state, and one action. No sound, no
     * vibration, no badge, no timestamp; tapping it opens the app. The system
     * already shows its own VPN key in the status bar.
     */
    private fun buildNotification(connecting: Boolean): Notification {
        val stopIntent = PendingIntent.getService(
            this,
            0,
            Intent(this, OstpVpnService::class.java).apply { action = "STOP" },
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val openIntent = PendingIntent.getActivity(
            this,
            1,
            packageManager.getLaunchIntentForPackage(packageName)
                ?.apply { addFlags(Intent.FLAG_ACTIVITY_SINGLE_TOP) },
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
        val state = if (connecting) "Connecting…" else "Connected"
        val title = profileName ?: "OSTP"

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_ostp_status)
            .setContentTitle(title)
            .setContentText(state)
            .setOngoing(true)
            .setSilent(true)
            .setOnlyAlertOnce(true)
            .setShowWhen(false)
            .setLocalOnly(true)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .setVisibility(NotificationCompat.VISIBILITY_PUBLIC)
            .setForegroundServiceBehavior(NotificationCompat.FOREGROUND_SERVICE_IMMEDIATE)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setContentIntent(openIntent)
            .addAction(0, if (connecting) "Cancel" else "Disconnect", stopIntent)
            .build()
    }

    fun updateNotification(connected: Boolean) {
        try {
            val nm = NotificationManagerCompat.from(this)
            nm.notify(NOTIF_ID, buildNotification(connecting = !connected))
        } catch (e: Throwable) {
            Log.e("OstpVpnService", "Failed to update notification", e)
        }
        // Refresh Quick Settings tile state
        OstpTileService.refresh()
    }

    private fun acquireWakeLock() {
        if (wakeLock == null) {
            val pm = getSystemService(POWER_SERVICE) as PowerManager
            wakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, WAKE_LOCK_TAG)
            wakeLock?.acquire(24 * 60 * 60 * 1000L) // Max 24h
            Log.d("OstpVpnService", "WakeLock acquired")
        }
    }

    private fun releaseWakeLock() {
        try {
            wakeLock?.let {
                if (it.isHeld) it.release()
            }
            wakeLock = null
            Log.d("OstpVpnService", "WakeLock released")
        } catch (e: Throwable) {
            Log.e("OstpVpnService", "Error releasing WakeLock", e)
        }
    }

    /**
     * Follows the system default network, which is the one a SIM or Wi-Fi switch changes.
     * A general INTERNET request also matches our own VPN and a second SIM kept up in the
     * background, which made the core reconnect at the wrong moment or for no reason.
     */
    private fun registerNetworkCallback() {
        if (networkCallback != null) return
        try {
            val cm = getSystemService(android.content.Context.CONNECTIVITY_SERVICE) as android.net.ConnectivityManager
            // Baseline: the network we are starting on is not a change.
            currentNetwork = cm.activeNetwork?.takeIf { !isVpn(cm, it) }
            currentAddresses = currentNetwork?.let { addressesOf(cm, it) } ?: emptySet()
            applyUnderlying(currentNetwork)

            val cb = object : android.net.ConnectivityManager.NetworkCallback() {
                override fun onAvailable(network: android.net.Network) {
                    mainHandler.post {
                        if (networkCallback == null || isVpn(cm, network)) return@post
                        if (network == currentNetwork) return@post
                        currentNetwork = network
                        currentAddresses = addressesOf(cm, network)
                        applyUnderlying(network)
                        scheduleNotify()
                    }
                }

                override fun onLost(network: android.net.Network) {
                    mainHandler.post {
                        if (networkCallback == null || network != currentNetwork) return@post
                        // Nothing to reconnect to yet: the next onAvailable signals the core.
                        currentNetwork = null
                        currentAddresses = emptySet()
                        mainHandler.removeCallbacks(notifyRust)
                        applyUnderlying(null)
                    }
                }

                override fun onLinkPropertiesChanged(network: android.net.Network, lp: android.net.LinkProperties) {
                    mainHandler.post {
                        if (networkCallback == null || network != currentNetwork) return@post
                        val addrs = lp.linkAddresses.map { it.address }.toSet()
                        if (addrs == currentAddresses) return@post
                        currentAddresses = addrs
                        scheduleNotify()
                    }
                }
            }
            networkCallback = cb
            cm.registerDefaultNetworkCallback(cb)
        } catch (e: Throwable) {
            networkCallback = null
            Log.e("OstpVpnService", "Failed to register NetworkCallback", e)
        }
    }

    private fun isVpn(cm: android.net.ConnectivityManager, network: android.net.Network): Boolean =
        cm.getNetworkCapabilities(network)?.hasTransport(android.net.NetworkCapabilities.TRANSPORT_VPN) == true

    private fun addressesOf(cm: android.net.ConnectivityManager, network: android.net.Network): Set<java.net.InetAddress> =
        cm.getLinkProperties(network)?.linkAddresses?.map { it.address }?.toSet() ?: emptySet()

    private fun applyUnderlying(network: android.net.Network?) {
        try {
            setUnderlyingNetworks(if (network != null) arrayOf(network) else null)
        } catch (e: Throwable) {
            Log.e("OstpVpnService", "setUnderlyingNetworks failed", e)
        }
    }

    // A SIM switch delivers several callbacks within a second; one signal after they settle.
    private fun scheduleNotify() {
        mainHandler.removeCallbacks(notifyRust)
        mainHandler.postDelayed(notifyRust, 800)
    }

    private fun unregisterNetworkCallback() {
        mainHandler.removeCallbacks(notifyRust)
        try {
            networkCallback?.let {
                val cm = getSystemService(android.content.Context.CONNECTIVITY_SERVICE) as android.net.ConnectivityManager
                cm.unregisterNetworkCallback(it)
            }
        } catch (e: Throwable) {
            Log.e("OstpVpnService", "Failed to unregister NetworkCallback", e)
        }
        networkCallback = null
        currentNetwork = null
        currentAddresses = emptySet()
    }

    private fun startVpn(configJson: String) {
        if (vpnInterface != null) {
            // Already up: a second START changes nothing.
            isStarting = false
            OstpTileService.refresh()
            return
        }

        acquireWakeLock()
        profileName = OstpTileService.profileName(configJson)

        try {
            val json = org.json.JSONObject(configJson)
            val dnsServer = json.optString("dns_server", "1.1.1.1")
            val localProxy = json.optJSONObject("local_proxy")?.optString("bind_addr", "127.0.0.1:1088") ?: "127.0.0.1:1088"

            val builder = Builder()
                .setSession("OSTP Tunnel")
                .addAddress("10.1.0.2", 24)
                .addAddress("fd00:1:fd00:1:fd00:1:fd00:1", 128)
                .addRoute("0.0.0.0", 0)
                .addRoute("::", 0)
                .addDnsServer(dnsServer)
                .setMtu(Math.max(1280, json.optJSONObject("ostp")?.optInt("mtu", 1140) ?: 1140))

            // Only the DNS the user chose (or the server's, or 1.1.1.1 by default).
            // Fixed fallbacks (1.1.1.1 and 8.8.8.8) used to be added too: with the
            // server's resolver or one of the user's own chosen, the phone still
            // asked Cloudflare and Google, past the server's filtering. Every DNS
            // query goes through the tunnel anyway, so a fallback adds no
            // reliability, only another resolver that sees the names.
            // NOTE: Do NOT add IPv6 DNS servers here — Android would send DNS
            // queries over IPv6, but our smoltcp TUN stack processes them as
            // IPv4 only, causing all DNS to silently fail on LTE (IPv6-only networks).

            // allowBypass() is deliberately not called: it would let apps opt out of the
            // tunnel. Per-app routing uses the allowed/disallowed application lists below.

            try {
                builder.allowFamily(android.system.OsConstants.AF_INET)
                builder.allowFamily(android.system.OsConstants.AF_INET6)
            } catch (e: Throwable) { }
                
            val appRules = json.optJSONObject("app_rules")
            val mode = appRules?.optString("mode", "bypass") ?: "bypass"
            val packages = appRules?.optJSONArray("packages")
            
            if (mode == "proxy") {
                if (packages != null) {
                    for (i in 0 until packages.length()) {
                        val pkg = packages.getString(i)
                        try {
                            builder.addAllowedApplication(pkg)
                        } catch (e: Throwable) {
                            Log.e("OstpVpnService", "Failed to add allowed application $pkg: $e")
                        }
                    }
                }
            } else {
                try {
                    builder.addDisallowedApplication(applicationContext.packageName)
                } catch (e: Throwable) {
                    Log.e("OstpVpnService", "Failed to disallow our own package: $e")
                }
                
                if (packages != null) {
                    for (i in 0 until packages.length()) {
                        val pkg = packages.getString(i)
                        try {
                            builder.addDisallowedApplication(pkg)
                        } catch (e: Throwable) {
                            Log.e("OstpVpnService", "Failed to add disallowed application $pkg: $e")
                        }
                    }
                }
            }

            // null means the consent was revoked or another VPN app is now the active one.
            vpnInterface = builder.establish()
            val fd = vpnInterface?.fd ?: throw Exception("The system gave no VPN interface. The permission may have been revoked.")
            
            // CRITICAL: Clear O_CLOEXEC so the child process inherits the TUN file descriptor
            try {
                android.system.Os.fcntlInt(vpnInterface!!.fileDescriptor, android.system.OsConstants.F_SETFD, 0)
            } catch (e: Throwable) {
                Log.e("OstpVpnService", "Failed to clear O_CLOEXEC", e)
            }

            val success = OstpClientSdk.startClient(configJson, fd, "", localProxy)
            if (success) {
                Log.i("OstpVpnService", "OSTP Rust Core started successfully")
                localProxyAddr = localProxy
                isRunning = true
                isStarting = false
                // The core is up, the server has not answered yet: "Connecting…"
                // until the watcher sees connection_state 2.
                linkState = 0
                updateNotification(connected = false)
                registerNetworkCallback()
                startWatcher()
            } else {
                Log.e("OstpVpnService", "Failed to start OSTP Rust Core")
                stopVpn()
            }

        } catch (e: Throwable) {
            Log.e("OstpVpnService", "Error starting VPN", e)
            android.os.Handler(android.os.Looper.getMainLooper()).post {
                android.widget.Toast.makeText(applicationContext, "Could not start the VPN: ${e.message}", android.widget.Toast.LENGTH_LONG).show()
            }
            stopVpn()
        }
    }

    /**
     * Follows the core's connection_state once a second: the notification and
     * the tile say "Connected" only when the server answered, and a core that
     * stopped on its own (the server closed the session, the key expired) ends
     * the tunnel instead of leaving a VPN that carries nothing.
     */
    private fun startWatcher() {
        stopWatcher()
        watchStartedAt = android.os.SystemClock.elapsedRealtime()
        coreEverUp = false
        zeroSince = 0L
        val ex = java.util.concurrent.Executors.newSingleThreadScheduledExecutor()
        watcher = ex
        ex.scheduleWithFixedDelay({
            val state = try {
                org.json.JSONObject(OstpClientSdk.getMetrics()).optInt("connection_state", 0)
            } catch (e: Throwable) {
                -1
            }
            if (state >= 0) mainHandler.post { onCoreState(ex, state) }
        }, 1, 1, java.util.concurrent.TimeUnit.SECONDS)
    }

    private fun stopWatcher() {
        watcher?.shutdownNow()
        watcher = null
    }

    private fun onCoreState(from: java.util.concurrent.ScheduledExecutorService, state: Int) {
        // A reading from a watcher already stopped (the tunnel ended or restarted) is dropped.
        if (from !== watcher || !isRunning) return
        val now = android.os.SystemClock.elapsedRealtime()
        if (state != 0) {
            coreEverUp = true
            zeroSince = 0L
        } else if (zeroSince == 0L) {
            zeroSince = now
        }
        // Anything short of 2 is shown as connecting; the notification and the
        // tile change only when the shown state does.
        val shown = if (state == 2) 2 else 1
        if (shown != linkState) {
            linkState = shown
            updateNotification(connected = shown == 2)
        }
        if (state == 0 && coreGone(coreEverUp, now - zeroSince, now - watchStartedAt)) {
            Log.w("OstpVpnService", "The core reports no connection; ending the tunnel")
            try {
                OstpClientSdk.addLog("The connection ended, so the VPN was turned off")
            } catch (_: Throwable) {}
            stopVpn()
        }
    }

    private fun stopVpn() {
        isRunning = false
        isStarting = false
        localProxyAddr = ""
        linkState = 0
        stopWatcher()
        releaseWakeLock()
        // Stop following the network first, so no late callback signals a core that is going away.
        unregisterNetworkCallback()

        // Each step is independent: a failure in the core must not leave the TUN fd open.
        try {
            OstpClientSdk.stopClient()
        } catch (e: Throwable) {
            Log.e("OstpVpnService", "Error stopping the core", e)
        }
        try {
            vpnInterface?.close()
        } catch (e: IOException) {
            Log.e("OstpVpnService", "Error closing VPN interface", e)
        }
        vpnInterface = null

        try {
            ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
        } catch (e: Throwable) {
            Log.e("OstpVpnService", "stopForeground failed", e)
        }
        OstpTileService.refresh()
        stopSelf()
    }

    override fun onDestroy() {
        super.onDestroy()
        // A quick stop+start can create the next instance before this one is destroyed;
        // its state is not ours to tear down.
        val ownsTunnel = synchronized(OstpVpnService::class.java) {
            // A START that reached this instance after stopVpn() but before onDestroy
            // moved `instance` and the generation to the new tunnel: leave it alone.
            val own = instance === this && ownedGeneration == generation
            if (instance === this) instance = null
            own
        }
        if (ownsTunnel) {
            stopVpn()
        } else {
            stopWatcher()
            releaseWakeLock()
        }
    }
}
