package com.ospab.ostp_client

import android.content.Intent
import android.net.VpnService
import androidx.annotation.NonNull
import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.graphics.Canvas
import android.util.Base64
import java.io.ByteArrayOutputStream

class MainActivity : FlutterActivity() {
    private val CHANNEL = "com.ospab.ostp/vpn"
    private val VPN_REQUEST_CODE = 0x0F
    private var pendingConfigJson: String? = null

    private fun getAppIconBase64(pm: PackageManager, appInfo: ApplicationInfo): String? {
        try {
            val drawable = pm.getApplicationIcon(appInfo)
            val width = 96
            val height = 96
            val bitmap = Bitmap.createBitmap(width, height, Bitmap.Config.ARGB_8888)
            val canvas = Canvas(bitmap)
            drawable.setBounds(0, 0, width, height)
            drawable.draw(canvas)
            
            val outputStream = ByteArrayOutputStream()
            bitmap.compress(Bitmap.CompressFormat.PNG, 90, outputStream)
            val byteArray = outputStream.toByteArray()
            return Base64.encodeToString(byteArray, Base64.NO_WRAP)
        } catch (e: Throwable) {
            return null
        }
    }

    override fun configureFlutterEngine(@NonNull flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, CHANNEL).setMethodCallHandler { call, result ->
            when (call.method) {
                "saveConfig" -> {
                    val configJson = call.argument<String>("configJson")
                    val prefs = getSharedPreferences("OstpPrefs", android.content.Context.MODE_PRIVATE)
                    prefs.edit().putString("latest_config_json", configJson).apply()
                    result.success(true)
                }
                "startTunnel" -> {
                    pendingConfigJson = call.argument<String>("configJson")
                    val intent = VpnService.prepare(this)
                    if (intent != null) {
                        startActivityForResult(intent, VPN_REQUEST_CODE)
                        result.success(true) 
                    } else {
                        startVpnService()
                        result.success(true)
                    }
                }
                "stopTunnel" -> {
                    try {
                        val intent = Intent(this, OstpVpnService::class.java)
                        intent.action = "STOP"
                        startService(intent)
                        result.success(true)
                    } catch (e: Throwable) {
                        result.error("ERROR", e.message, null)
                    }
                }
                "getLogs" -> {
                    try {
                        val logs = net.ostp.client.OstpClientSdk.getLogs()
                        result.success(logs ?: "[]")
                    } catch (e: Throwable) {
                        result.error("ERROR", e.message ?: "Unknown JNI Error", null)
                    }
                }
                "clearLogs" -> {
                    try {
                        net.ostp.client.OstpClientSdk.getLogs() // Drain
                        result.success(true)
                    } catch (e: Throwable) {
                        result.error("ERROR", e.message, null)
                    }
                }
                "isRunning" -> {
                    result.success(OstpVpnService.isRunning)
                }
                "getMetrics" -> {
                    try {
                        val metrics = net.ostp.client.OstpClientSdk.getMetrics()
                        result.success(metrics ?: "{}")
                    } catch (e: Throwable) {
                        result.error("ERROR", e.message, null)
                    }
                }
                "getInstalledApps" -> {
                    try {
                        val pm = packageManager
                        val apps = pm.getInstalledApplications(PackageManager.GET_META_DATA)
                        val list = apps.map { app ->
                            val isSystem = ((app.flags and ApplicationInfo.FLAG_SYSTEM) != 0) &&
                                           (pm.getLaunchIntentForPackage(app.packageName) == null)
                            val iconBase64 = getAppIconBase64(pm, app)
                            mapOf(
                                "name" to pm.getApplicationLabel(app).toString(),
                                "package" to app.packageName,
                                "isSystem" to isSystem,
                                "icon" to (iconBase64 ?: "")
                            )
                        }
                        result.success(list)
                    } catch (e: Exception) {
                        result.error("ERROR", e.message, null)
                    }
                }
                else -> result.notImplemented()
            }
        }
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        if (requestCode == VPN_REQUEST_CODE && resultCode == RESULT_OK) {
            startVpnService()
        }
        super.onActivityResult(requestCode, resultCode, data)
    }

    private fun startVpnService() {
        val intent = Intent(this, OstpVpnService::class.java)
        intent.action = "START"
        if (pendingConfigJson != null) {
            intent.putExtra("configJson", pendingConfigJson)
        }
        startService(intent)
    }
}
