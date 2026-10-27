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
    // Answer owed to Dart for a startTunnel that is waiting for the system VPN
    // consent dialog. Replied to exactly once: on the dialog result or on destroy.
    private var pendingStartResult: MethodChannel.Result? = null
    // A config larger than this is a bug or garbage, not a profile; it would not fit an Intent extra either.
    private val MAX_CONFIG_BYTES = 256 * 1024

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
                    if (configJson == null || configJson.length > MAX_CONFIG_BYTES) {
                        result.error("BAD_CONFIG", "Config is missing or too large", null)
                    } else {
                        try {
                            val prefs = getSharedPreferences("OstpPrefs", android.content.Context.MODE_PRIVATE)
                            prefs.edit().putString("latest_config_json", configJson).apply()
                            result.success(true)
                        } catch (e: Throwable) {
                            result.error("ERROR", e.message, null)
                        }
                    }
                }
                "startTunnel" -> {
                    val configJson = call.argument<String>("configJson")
                    if (configJson == null || configJson.length > MAX_CONFIG_BYTES) {
                        result.error("BAD_CONFIG", "Config is missing or too large", null)
                    } else if (pendingStartResult != null) {
                        // The consent dialog from an earlier tap is still open.
                        result.error("BUSY", "Waiting for the VPN permission dialog", null)
                    } else {
                        try {
                            pendingConfigJson = configJson
                            val intent = VpnService.prepare(this)
                            if (intent != null) {
                                pendingStartResult = result
                                startActivityForResult(intent, VPN_REQUEST_CODE)
                            } else {
                                startVpnService()
                                result.success(true)
                            }
                        } catch (e: Throwable) {
                            pendingStartResult = null
                            pendingConfigJson = null
                            result.error("ERROR", e.message, null)
                        }
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
                        // Surfaced into the in-app log viewer (not just logcat) so a
                        // broken traffic counter is diagnosable from a user's bug
                        // report without adb access.
                        android.util.Log.e("MainActivity", "getMetrics failed", e)
                        try {
                            net.ostp.client.OstpClientSdk.addLog("getMetrics failed: ${e.javaClass.simpleName}: ${e.message}")
                        } catch (_: Throwable) {}
                        result.error("ERROR", e.message, null)
                    }
                }
                "runProberMatrix" -> {
                    // Real handshakes over every address x transport combo can
                    // take several seconds total — same reasoning as
                    // getInstalledApps below: never block the UI thread with it.
                    val requestJson = call.argument<String>("requestJson") ?: "{}"
                    Thread {
                        try {
                            val report = net.ostp.client.OstpClientSdk.runProberMatrix(requestJson)
                            runOnUiThread { result.success(report) }
                        } catch (e: Throwable) {
                            runOnUiThread { result.error("ERROR", e.message, null) }
                        }
                    }.start()
                }
                "buildTag" -> {
                    try {
                        result.success(net.ostp.client.OstpClientSdk.buildTag())
                    } catch (e: Throwable) {
                        result.error("ERROR", e.message, null)
                    }
                }
                "checkForUpdates" -> {
                    // A network round trip to GitHub: never on the UI thread.
                    Thread {
                        try {
                            val json = net.ostp.client.OstpClientSdk.checkForUpdates()
                            runOnUiThread { result.success(json) }
                        } catch (e: Throwable) {
                            runOnUiThread { result.error("ERROR", e.message, null) }
                        }
                    }.start()
                }
                "addLog" -> {
                    val message = call.argument<String>("message") ?: ""
                    try {
                        net.ostp.client.OstpClientSdk.addLog(message)
                    } catch (_: Throwable) {}
                    result.success(null)
                }
                "serversCall" -> {
                    // SSH round trips, and an install takes minutes: never on the UI thread.
                    val requestJson = call.argument<String>("requestJson") ?: "{}"
                    val dataDir = filesDir.absolutePath
                    Thread {
                        try {
                            val key = ServerVault.masterKeyHex(applicationContext)
                            val reply = net.ostp.client.OstpClientSdk.serversCall(dataDir, key, requestJson)
                            runOnUiThread { result.success(reply) }
                        } catch (e: Throwable) {
                            runOnUiThread { result.error("ERROR", e.message, null) }
                        }
                    }.start()
                }
                "fetchSubscription" -> {
                    // A network round trip with a TLS handshake: never on the UI thread.
                    val url = call.argument<String>("url") ?: ""
                    Thread {
                        try {
                            val doc = net.ostp.client.OstpClientSdk.fetchSubscription(url)
                            runOnUiThread { result.success(doc) }
                        } catch (e: Throwable) {
                            runOnUiThread { result.error("ERROR", e.message, null) }
                        }
                    }.start()
                }
                "runProberTtlScan" -> {
                    // A full TTL sweep (up to max_ttl attempts, each with its
                    // own timeout) can take tens of seconds — background thread
                    // is mandatory here, not just good practice.
                    val requestJson = call.argument<String>("requestJson") ?: "{}"
                    Thread {
                        try {
                            val report = net.ostp.client.OstpClientSdk.runProberTtlScan(requestJson)
                            runOnUiThread { result.success(report) }
                        } catch (e: Throwable) {
                            runOnUiThread { result.error("ERROR", e.message, null) }
                        }
                    }.start()
                }
                "runProberDpiBattery" -> {
                    // The full DPI/TSPU differential battery (SNI, HTTP Host,
                    // DNS hijack/injection, CONNECT hijack, RST injection,
                    // UDP throttle...) takes ~10s of real network round trips
                    // — same as the matrix/TTL scans above, background thread.
                    Thread {
                        try {
                            val report = net.ostp.client.OstpClientSdk.runProberDpiBattery()
                            runOnUiThread { result.success(report) }
                        } catch (e: Throwable) {
                            runOnUiThread { result.error("ERROR", e.message, null) }
                        }
                    }.start()
                }
                "getInstalledApps" -> {
                    // MethodChannel handlers run on the main/UI thread by default.
                    // Enumerating every installed package AND decoding+re-encoding
                    // each one's icon to PNG/base64 is expensive (100+ apps is
                    // common) — done inline here it blocked the main thread for
                    // 10-15s, during which Flutter couldn't render ANY frame, not
                    // even the "loading" spinner, so the screen just appeared to
                    // hang before jumping straight to the fully-loaded list.
                    // Do the work on a background thread; only the final
                    // `result.success(...)` needs to hop back onto the UI thread.
                    val pm = packageManager
                    Thread {
                        try {
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
                            runOnUiThread { result.success(list) }
                        } catch (e: Exception) {
                            runOnUiThread { result.error("ERROR", e.message, null) }
                        }
                    }.start()
                }
                else -> result.notImplemented()
            }
        }
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        if (requestCode == VPN_REQUEST_CODE) {
            val reply = pendingStartResult
            pendingStartResult = null
            if (resultCode == RESULT_OK) {
                try {
                    startVpnService()
                    reply?.success(true)
                } catch (e: Throwable) {
                    reply?.error("ERROR", e.message, null)
                }
            } else {
                // Denied or dismissed: nothing was started, say so instead of leaving Dart to time out.
                pendingConfigJson = null
                reply?.success(false)
            }
        }
        super.onActivityResult(requestCode, resultCode, data)
    }

    override fun onDestroy() {
        // The dialog result can no longer reach a live engine; do not leave Dart waiting on it.
        pendingStartResult?.let {
            pendingStartResult = null
            try { it.success(false) } catch (_: Throwable) {}
        }
        super.onDestroy()
    }

    private fun startVpnService() {
        val intent = Intent(this, OstpVpnService::class.java)
        intent.action = "START"
        val cfg = pendingConfigJson ?: return
        pendingConfigJson = null
        intent.putExtra("configJson", cfg)
        androidx.core.content.ContextCompat.startForegroundService(this, intent)
        // Ask to be exempt from battery optimization so Doze does not freeze the
        // service (which drops the tunnel AND stops the in-process reconnect from
        // ever running). Only prompts if not already exempt; runs after the VPN
        // consent so the two system dialogs do not stack.
        requestBatteryExemptionIfNeeded()
    }

    private fun requestBatteryExemptionIfNeeded() {
        try {
            // Asked once: a user who declined should not meet the dialog on every connect.
            val prefs = getSharedPreferences("OstpPrefs", android.content.Context.MODE_PRIVATE)
            if (prefs.getBoolean("battery_prompted", false)) return
            val pm = getSystemService(android.content.Context.POWER_SERVICE) as android.os.PowerManager
            if (!pm.isIgnoringBatteryOptimizations(packageName)) {
                prefs.edit().putBoolean("battery_prompted", true).apply()
                val intent = Intent(android.provider.Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS)
                intent.data = android.net.Uri.parse("package:$packageName")
                intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                startActivity(intent)
            }
        } catch (e: Throwable) {
            android.util.Log.e("MainActivity", "Battery exemption request failed", e)
        }
    }
}
