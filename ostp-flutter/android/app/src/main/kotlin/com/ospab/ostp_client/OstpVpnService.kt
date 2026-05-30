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

@Keep
class OstpVpnService : VpnService() {

    @Keep
    companion object {
        @Keep
        var isRunning = false
        @Keep
        var instance: OstpVpnService? = null

        private const val NOTIF_ID = 1001
        private const val CHANNEL_ID = "ostp_vpn_channel"
        private const val WAKE_LOCK_TAG = "ostp:vpn_wakelock"

        /**
         * Called by OstpClientSdk.notifyNetworkChanged() JNI thunk.
         */
        @Keep
        @JvmStatic
        fun onNetworkChanged() {
            android.util.Log.d("OstpVpnService", "onNetworkChanged() signaled to Rust bridge")
        }
    }

    private var vpnInterface: ParcelFileDescriptor? = null
    private var wakeLock: PowerManager.WakeLock? = null

    override fun onCreate() {
        super.onCreate()
        instance = this
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        val action = intent?.action
        if (action == "START") {
            val configJson = intent.getStringExtra("configJson") ?: return START_NOT_STICKY
            // Launch foreground immediately so Android doesn't kill us
            startForeground(NOTIF_ID, buildNotification(connecting = true))
            startVpn(configJson)
        } else if (action == "STOP") {
            stopVpn()
        }
        return START_STICKY
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "OSTP VPN",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "OSTP VPN connection status"
                setShowBadge(false)
            }
            val nm = getSystemService(NotificationManager::class.java)
            nm.createNotificationChannel(channel)
        }
    }

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

        val (statusText, actionLabel) = if (connecting) {
            Pair("Подключение...", "Отмена")
        } else {
            Pair("Подключено", "Отключить")
        }

        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("OSTP VPN")
            .setContentText(statusText)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setOngoing(true)
            .setShowWhen(false)
            .setContentIntent(openIntent)
            .addAction(android.R.drawable.ic_delete, actionLabel, stopIntent)
            .setPriority(NotificationCompat.PRIORITY_LOW)
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
        OstpTileService.requestListeningState(applicationContext)
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

    private fun startVpn(configJson: String) {
        if (vpnInterface != null) return

        acquireWakeLock()

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
                .setMtu(json.optJSONObject("ostp")?.optInt("mtu", 1280) ?: 1280)
                
            try { builder.addDnsServer("8.8.8.8") } catch (e: Throwable) {}
            try { builder.addDnsServer("2001:4860:4860::8888") } catch (e: Throwable) {}
            try { builder.addDnsServer("2606:4700:4700::1111") } catch (e: Throwable) {}

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                builder.allowBypass()
            }
                
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

            vpnInterface = builder.establish()
            val fd = vpnInterface?.fd ?: throw Exception("Failed to get VPN FD")
            
            // CRITICAL: Clear O_CLOEXEC so the child process inherits the TUN file descriptor
            try {
                android.system.Os.fcntlInt(vpnInterface!!.fileDescriptor, android.system.OsConstants.F_SETFD, 0)
            } catch (e: Throwable) {
                Log.e("OstpVpnService", "Failed to clear O_CLOEXEC", e)
            }

            val success = OstpClientSdk.startClient(configJson, fd, "", localProxy)
            if (success) {
                Log.i("OstpVpnService", "OSTP Rust Core started successfully")
                isRunning = true
                updateNotification(connected = true)
            } else {
                Log.e("OstpVpnService", "Failed to start OSTP Rust Core")
                stopVpn()
            }

        } catch (e: Throwable) {
            Log.e("OstpVpnService", "Error starting VPN", e)
            stopVpn()
        }
    }

    private fun stopVpn() {
        isRunning = false
        releaseWakeLock()

        try {
            OstpClientSdk.stopClient()
            vpnInterface?.close()
            vpnInterface = null
        } catch (e: IOException) {
            Log.e("OstpVpnService", "Error closing VPN interface", e)
        }

        stopForeground(true)
        OstpTileService.requestListeningState(applicationContext)
        stopSelf()
    }

    override fun onDestroy() {
        super.onDestroy()
        instance = null
        stopVpn()
    }
}
