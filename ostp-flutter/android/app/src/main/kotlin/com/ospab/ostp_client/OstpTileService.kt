package com.ospab.ostp_client

import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.graphics.drawable.Icon
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import androidx.annotation.Keep
import androidx.annotation.RequiresApi

/**
 * The Quick Settings tile: one tap connects or disconnects with the profile
 * last used in the app; a long press opens the app (the QS_TILE_PREFERENCES
 * intent filter on MainActivity). The tile shows the real state: connected to
 * the server, connecting, off, or no profile to connect to.
 *
 * Not an active tile (no META_DATA_ACTIVE_TILE): the system binds it and calls
 * onStartListening every time the shade opens, so a state that changed while
 * the shade was closed (or a process that died with its VPN) is never shown
 * stale. While the shade is open the service pushes changes through [refresh].
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
        listening = this
        updateTile()
    }

    override fun onStopListening() {
        if (listening === this) listening = null
        super.onStopListening()
    }

    override fun onDestroy() {
        if (listening === this) listening = null
        super.onDestroy()
    }

    override fun onClick() {
        super.onClick()
        if (OstpVpnService.isRunning || OstpVpnService.isStarting) {
            // A running foreground service may be sent another command from the background.
            try {
                startService(Intent(this, OstpVpnService::class.java).apply { action = "STOP" })
            } catch (e: Throwable) {
                android.util.Log.e("OstpTileService", "Could not stop the VPN service", e)
            }
            return
        }
        // Behind the lock screen the tile asks to unlock first, so the VPN is
        // never started by someone holding a locked phone. unlockAndRun runs the
        // action only after a successful unlock (TileService#unlockAndRun).
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
            androidx.core.content.ContextCompat.startForegroundService(this, startIntent)
        } catch (e: Throwable) {
            // The system may refuse a foreground start (background limits): the tile
            // stays off instead of showing a tunnel that does not exist.
            android.util.Log.e("OstpTileService", "Could not start the VPN service", e)
        }
        // The service sets isStarting in onStartCommand and pushes every later
        // change through refresh(); this shows whatever is true right now.
        updateTile()
    }

    /**
     * Opens the app and closes the shade. startActivityAndCollapse(Intent) is
     * deprecated in API 34 and "throws UnsupportedOperationException if called
     * in versions UPSIDE_DOWN_CAKE and up" (TileService reference), so the
     * PendingIntent overload (added in API 34) is used there.
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
        // getQsTile is only valid between onStartListening and onStopListening
        // (TileService#getQsTile); outside it the update is simply not shown.
        val tile = qsTile ?: return
        val config = savedConfig()
        val view = tileView(
            running = OstpVpnService.isRunning,
            starting = OstpVpnService.isStarting,
            linkState = OstpVpnService.linkState,
            hasConfig = config != null,
            profile = profileName(config),
        )
        tile.icon = Icon.createWithResource(this, R.drawable.ic_ostp_status)
        tile.state = if (view.active) Tile.STATE_ACTIVE else Tile.STATE_INACTIVE
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            // Tile#setSubtitle exists from API 29; older systems show the label only.
            tile.label = "OSTP"
            tile.subtitle = view.subtitle
        } else {
            tile.label = view.subtitle
        }
        tile.contentDescription = "OSTP: ${view.subtitle}"
        tile.updateTile()
    }

    /** What the tile shows: on or off, and the line under its label. */
    data class TileView(val active: Boolean, val subtitle: String)

    companion object {
        // The bound tile while the shade is open, so state changes reach it live.
        @Volatile
        private var listening: OstpTileService? = null
        // Lazy: the pure functions below are unit-tested on the JVM, where Looper is a stub.
        private val main by lazy { Handler(Looper.getMainLooper()) }

        /**
         * The tile for a service state. [linkState] is the core's connection_state
         * (0 none, 1 handshake or reconnect, 2 connected): the tile says connected
         * only once the server answered, not when the core merely started.
         */
        fun tileView(running: Boolean, starting: Boolean, linkState: Int, hasConfig: Boolean, profile: String?): TileView = when {
            running && linkState == 2 -> TileView(true, profile ?: "Connected")
            running || starting -> TileView(true, "Connecting…")
            !hasConfig -> TileView(false, "No profile")
            else -> TileView(false, profile ?: "Off")
        }

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

        /**
         * Shows the current service state on the tile if the shade is open; called
         * by the VPN service on every change. TileService.requestListeningState
         * would not do it: "This method is only applicable to tiles that have
         * META_DATA_ACTIVE_TILE defined as true ... and will do nothing otherwise"
         * (TileService reference). When the shade is closed there is nothing to
         * do: the next onStartListening reads the state anew.
         */
        @Keep
        fun refresh() {
            main.post { listening?.updateTile() }
        }
    }
}
