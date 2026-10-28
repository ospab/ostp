package com.ospab.ostp_client

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.provider.Settings
import androidx.core.content.FileProvider
import org.json.JSONObject
import java.io.File
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

/**
 * Downloads this app's APK from a GitHub release and installs it through the
 * system installer. Nothing here runs unless the user tapped "Update now".
 * The APK is signed with the installed app's key, so Android treats it as an update.
 */
class AppUpdater(private val context: Context) {
    class UpdateException(message: String) : Exception(message)

    val downloaded = AtomicLong(0)
    val total = AtomicLong(0)
    private val cancelled = AtomicBoolean(false)

    fun cancel() {
        cancelled.set(true)
    }

    /** Blocking; call off the UI thread. Returns the verified APK. */
    fun download(tag: String): File {
        cancelled.set(false)
        downloaded.set(0)
        total.set(0)
        if (tag.isEmpty() || !tag.all { it.isLetterOrDigit() && it.code < 128 || it == '.' || it == '-' }) {
            throw UpdateException("Not a release tag: $tag")
        }
        val abi = deviceAbi() ?: throw UpdateException("There is no build for this device (${Build.SUPPORTED_ABIS.joinToString()})")
        val name = "ostp-android-$abi.apk"

        val release = JSONObject(String(httpGet("https://api.github.com/repos/ospab/ostp/releases/tags/$tag", "application/vnd.github+json", null)))
        val assets = release.optJSONArray("assets") ?: throw UpdateException("Release $tag has no files")
        var asset: JSONObject? = null
        for (i in 0 until assets.length()) {
            val a = assets.getJSONObject(i)
            if (a.optString("name") == name) asset = a
        }
        if (asset == null) throw UpdateException("Release $tag has no $name")

        // Without the published hash nothing proves the file is the one CI built.
        val sha = asset.optString("digest").removePrefix("sha256:").lowercase()
        if (!asset.optString("digest").startsWith("sha256:") || sha.length != 64 || !sha.all { it in '0'..'9' || it in 'a'..'f' }) {
            throw UpdateException("GitHub gives no SHA-256 for $name, so it was not installed")
        }
        val size = asset.optLong("size", 0)
        if (size <= 0 || size > MAX_APK_BYTES) throw UpdateException("$name has an unexpected size ($size bytes)")
        total.set(size)

        val dir = File(context.cacheDir, "updates")
        dir.deleteRecursively()
        if (!dir.mkdirs()) throw UpdateException("Cannot create the download folder")
        val file = File(dir, name)
        try {
            val md = MessageDigest.getInstance("SHA-256")
            val body = httpGet(asset.getString("browser_download_url"), "application/octet-stream", Sink(file, md, size))
            if (body.isNotEmpty()) throw IOException("Unexpected response body")
            if (downloaded.get() != size) throw UpdateException("The download was cut short (${downloaded.get()} of $size bytes)")
            val hex = md.digest().joinToString("") { "%02x".format(it) }
            if (hex != sha) throw UpdateException("The downloaded file does not match the SHA-256 GitHub published, so it was not installed")
        } catch (e: Throwable) {
            file.delete()
            throw e
        }
        return file
    }

    /**
     * Starts the system installer. Returns false when Android does not let this
     * app install packages yet; the settings screen for that is opened instead.
     */
    fun install(file: File, launcher: Context): Boolean {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O && !context.packageManager.canRequestPackageInstalls()) {
            launcher.startActivity(
                Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES, Uri.parse("package:${context.packageName}"))
                    .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            )
            return false
        }
        val uri = FileProvider.getUriForFile(context, "${context.packageName}.updates", file)
        launcher.startActivity(
            Intent(Intent.ACTION_VIEW)
                .setDataAndType(uri, "application/vnd.android.package-archive")
                .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_ACTIVITY_NEW_TASK)
        )
        return true
    }

    private fun deviceAbi(): String? =
        Build.SUPPORTED_ABIS.firstOrNull { it == "arm64-v8a" || it == "armeabi-v7a" }

    private class Sink(val file: File, val md: MessageDigest, val limit: Long)

    /** GET with manual redirects kept on GitHub's hosts. A sink streams the body to a file and returns an empty array. */
    private fun httpGet(start: String, accept: String, sink: Sink?): ByteArray {
        var url = start
        repeat(6) {
            val u = URL(url)
            val host = u.host
            if (u.protocol != "https" || !(host == "github.com" || host == "api.github.com" || host.endsWith(".githubusercontent.com"))) {
                throw UpdateException("The download was redirected to $host, which is not GitHub")
            }
            val c = u.openConnection() as HttpURLConnection
            try {
                c.instanceFollowRedirects = false
                c.connectTimeout = 15_000
                c.readTimeout = 30_000
                c.setRequestProperty("Accept", accept)
                c.setRequestProperty("User-Agent", "ostp-android")
                when (val code = c.responseCode) {
                    200 -> {
                        if (sink == null) return c.inputStream.use { it.readBytes() }
                        sink.file.outputStream().use { out ->
                            c.inputStream.use { input ->
                                val buf = ByteArray(64 * 1024)
                                while (true) {
                                    if (cancelled.get()) throw UpdateException("Cancelled")
                                    val n = input.read(buf)
                                    if (n < 0) break
                                    if (downloaded.get() + n > sink.limit) throw UpdateException("The download is larger than GitHub said")
                                    sink.md.update(buf, 0, n)
                                    out.write(buf, 0, n)
                                    downloaded.addAndGet(n.toLong())
                                }
                            }
                        }
                        return ByteArray(0)
                    }
                    301, 302, 303, 307, 308 -> {
                        val loc = c.getHeaderField("Location") ?: throw UpdateException("A redirect without a location")
                        url = URL(u, loc).toString()
                    }
                    404 -> throw UpdateException("GitHub has no such release")
                    403, 429 -> throw UpdateException("GitHub is rate-limiting requests from this address; try again later")
                    else -> throw UpdateException("GitHub answered HTTP $code")
                }
            } finally {
                c.disconnect()
            }
        }
        throw UpdateException("Too many redirects")
    }

    private companion object {
        // Larger than any build of the app; a bigger answer is not ours.
        const val MAX_APK_BYTES = 300L * 1024 * 1024
    }
}
