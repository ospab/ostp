package com.ospab.ostp_client

import android.app.PendingIntent
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.graphics.drawable.Icon
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import androidx.annotation.Keep
import androidx.annotation.RequiresApi

/**
 * The Quick Settings tile: one tap connects or disconnects with the profile
 * last used in the app; a long press opens the app (the QS_TILE_PREFERENCES
 * intent filter on MainActivity). The tile shows the real state of the
 * service: on, connecting, off, or no profile to connect to.
 */
@Keep
@RequiresApi(Build.VERSION_CODES.N)
class OstpTileService : TileService() {

    override fun onTileAdded() {
        super.onTileAdded()
        updateTile()
    }

    override fun onStartListening() {
        super.onStartListening()
        updateTile()
    }

    override fun onClick() {
        super.onClick()
        if (OstpVpnService.isRunning || OstpVpnService.isStarting) {
            startService(Intent(this, OstpVpnService::class.java).apply { action = "STOP" })
            return
        }
        // Behind the lock screen the tile asks to unlock first, so the VPN is
        // never started by someone holding a locked phone.
        if (isLocked) {
            unlockAndRun { connect() }
        } else {
            connect()
        }
    }

    private fun connect() {
        val configJson = savedConfig()
        if (configJson == null) {
            // No active profile (or nothing saved yet): there is nothing to connect to.
            openApp()
            return
        }
        // The VPN permission is asked in the app: a tile cannot show that dialog.
        if (android.net.VpnService.prepare(this) != null) {
            openApp()
            return
        }
        val startIntent = Intent(this, OstpVpnService::class.java).apply {
            action = "START"
            putExtra("configJson", configJson)
        }
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                startForegroundService(startIntent)
            } else {
                startService(startIntent)
            }
        } catch (e: Throwable) {
            // The system may refuse a foreground start (background limits): the tile
            // stays off instead of showing a tunnel that does not exist.
            android.util.Log.e("OstpTileService", "Could not start the VPN service", e)
        }
        // Shown as connecting right away; the service reports the real state
        // through requestListeningState.
        updateTile()
    }

    /**
     * Opens the app and closes the shade. Android 14 refuses the Intent form of
     * startActivityAndCollapse (UnsupportedOperationException for apps that
     * target it), so a PendingIntent is used there.
     */
    private fun openApp() {
        val intent = packageManager.getLaunchIntentForPackage(packageName)?.apply {
            addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP)
        } ?: return
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                val pi = PendingIntent.getActivity(this, 0, intent, PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT)
                startActivityAndCollapse(pi)
            } else {
                @Suppress("DEPRECATION")
                startActivityAndCollapse(intent)
            }
        } catch (e: Throwable) {
            android.util.Log.e("OstpTileService", "Could not open the app", e)
        }
    }

    /** The config the app saved for its active profile, or null when it cannot connect. */
    private fun savedConfig(): String? {
        val json = getSharedPreferences("OstpPrefs", Context.MODE_PRIVATE).getString("latest_config_json", null)
        return json?.takeIf { usableConfig(it) }
    }

    private fun updateTile() {
        val tile = qsTile ?: return
        val config = savedConfig()
        tile.icon = Icon.createWithResource(this, R.drawable.ic_ostp_status)
        tile.label = "OSTP"
        val subtitle: String
        when {
            OstpVpnService.isRunning -> {
                tile.state = Tile.STATE_ACTIVE
                subtitle = profileName(config) ?: "Connected"
            }
            OstpVpnService.isStarting -> {
                tile.state = Tile.STATE_ACTIVE
                subtitle = "Connecting…"
            }
            config == null -> {
                tile.state = Tile.STATE_INACTIVE
                subtitle = "No profile"
            }
            else -> {
                tile.state = Tile.STATE_INACTIVE
                subtitle = profileName(config) ?: "Off"
            }
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            tile.subtitle = subtitle
        }
        tile.contentDescription = "OSTP: $subtitle"
        tile.updateTile()
    }

    companion object {
        /**
         * The app's config keeps the server and the key under "ostp"; the tile
         * used to look for them at the top level, found nothing, and opened the
         * app instead of connecting.
         */
        fun usableConfig(configJson: String?): Boolean {
            if (configJson.isNullOrEmpty()) return false
            return try {
                val o = org.json.JSONObject(configJson).optJSONObject("ostp") ?: return false
                o.optString("server_addr").isNotEmpty() && o.optString("access_key").isNotEmpty()
            } catch (_: Throwable) {
                false
            }
        }

        /** The profile name the app saved with the config, if any. */
        fun profileName(configJson: String?): String? = try {
            configJson?.let { org.json.JSONObject(it).optString("profile_name").takeIf { n -> n.isNotBlank() }?.take(40) }
        } catch (_: Throwable) {
            null
        }

        /** Asks the system to refresh the tile; called by the service on every state change. */
        @Keep
        fun requestListeningState(context: Context) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                try {
                    requestListeningState(context, ComponentName(context, OstpTileService::class.java))
                } catch (_: Exception) {
                    // The tile may not be in the panel: nothing to refresh.
                }
            }
        }
    }
}
