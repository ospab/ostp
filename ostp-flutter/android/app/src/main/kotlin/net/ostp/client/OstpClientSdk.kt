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
        val service = com.ospab.ostp_client.OstpVpnService.instance
        if (service != null) {
            val res = service.protect(fd)
            android.util.Log.i("OstpClientSdk", "VpnService.protect(socketFd=$fd) -> success=$res")
            return res
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
}
