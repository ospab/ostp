package com.ospab.ostp_client

import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.os.Build
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import androidx.annotation.Keep
import androidx.annotation.RequiresApi

@Keep
@RequiresApi(Build.VERSION_CODES.N)
class OstpTileService : TileService() {

    override fun onStartListening() {
        super.onStartListening()
        updateTile()
    }

    override fun onClick() {
        super.onClick()
        if (OstpVpnService.isRunning) {
            // Отключить VPN
            val stopIntent = Intent(this, OstpVpnService::class.java).apply { action = "STOP" }
            startService(stopIntent)
            // Обновим плитку сразу
            qsTile?.state = Tile.STATE_INACTIVE
            qsTile?.label = "OSTP VPN"
            qsTile?.updateTile()
        } else {
            // Включить VPN напрямую
            val prefs = getSharedPreferences("OstpPrefs", Context.MODE_PRIVATE)
            val configJson = prefs.getString("latest_config_json", null)
            
            if (configJson != null) {
                // Check if VPN consent is needed
                val vpnIntent = android.net.VpnService.prepare(this)
                if (vpnIntent != null) {
                    // Consent needed, launch app
                    val appIntent = packageManager.getLaunchIntentForPackage(packageName)?.apply {
                        addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP)
                    }
                    if (appIntent != null) {
                        startActivityAndCollapse(appIntent)
                    }
                    return
                }

                val startIntent = Intent(this, OstpVpnService::class.java).apply {
                    action = "START"
                    putExtra("configJson", configJson)
                }
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                    startForegroundService(startIntent)
                } else {
                    startService(startIntent)
                }
                qsTile?.state = Tile.STATE_ACTIVE
                qsTile?.label = "OSTP VPN"
                qsTile?.updateTile()
            } else {
                // Если конфигурация еще не сохранена, открыть приложение
                val appIntent = packageManager.getLaunchIntentForPackage(packageName)?.apply {
                    addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_ACTIVITY_SINGLE_TOP)
                    putExtra("tile_connect", true)
                }
                if (appIntent != null) {
                    startActivityAndCollapse(appIntent)
                }
            }
        }
    }

    private fun updateTile() {
        val tile = qsTile ?: return
        if (OstpVpnService.isRunning) {
            tile.label = "OSTP VPN"
            tile.state = Tile.STATE_ACTIVE
        } else {
            tile.label = "OSTP VPN"
            tile.state = Tile.STATE_INACTIVE
        }
        tile.updateTile()
    }

    companion object {
        /**
         * Запрашивает обновление плитки быстрых настроек.
         * Вызывается из OstpVpnService при изменении состояния.
         */
        @Keep
        fun requestListeningState(context: Context) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                try {
                    requestListeningState(
                        context,
                        ComponentName(context, OstpTileService::class.java)
                    )
                } catch (e: Exception) {
                    // Плитка может быть не добавлена в панель — это нормально
                }
            }
        }
    }
}
