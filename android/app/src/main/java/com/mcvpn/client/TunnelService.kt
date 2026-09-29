package com.mcvpn.client

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import android.os.SystemClock
import org.json.JSONObject

class TunnelService : VpnService() {
    companion object {
        // Declared before init: a missing/incompatible native library must
        // become a readable error in the UI, not a crash on first touch.
        @Volatile var libError: String? = null

        init {
            try {
                System.loadLibrary("mcvpn")
            } catch (t: Throwable) {
                libError = "native library failed to load: ${t.message}"
            }
        }

        @Volatile var running = false
        @Volatile var connecting = false
        @Volatile var lastStats = "{}"
        @Volatile var lastError = ""
        @Volatile var lastIp = ""
        @Volatile var lastLog = ""
        @Volatile var connectedAtMs = 0L
        const val CHANNEL_ID = "mcvpn-tunnel"
    }

    private external fun nativeConnect(server: String, port: Int, token: String): String
    private external fun nativeStart(fd: Int): Boolean
    private external fun nativeStop()
    private external fun nativeGetStats(): String
    private external fun nativeGetLog(): String

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        try {
            when (intent?.getStringExtra("action")) {
                "connect" -> startVpn(intent)
                else -> stopVpn()
            }
        } catch (t: Throwable) {
            fail("${t.javaClass.simpleName}: ${t.message}")
        }
        return START_NOT_STICKY
    }

    override fun onDestroy() {
        stopVpn()
        super.onDestroy()
    }

    // User revoked VPN permission from system settings.
    override fun onRevoke() {
        stopVpn()
    }

    private fun refreshLog() {
        lastLog = try {
            nativeGetLog()
        } catch (t: Throwable) {
            "log unavailable: ${t.message}"
        }
    }

    /** Terminal failure: record why, release EVERYTHING (native session included). */
    private fun fail(message: String) {
        lastError = message
        running = false
        connecting = false
        lastIp = ""
        try {
            nativeStop()
        } catch (_: Throwable) {
        }
        refreshLog()
        try {
            stopForeground(STOP_FOREGROUND_REMOVE)
        } catch (_: Throwable) {
        }
        stopSelf()
    }

    private fun startVpn(intent: Intent) {
        if (connecting || running) {
            return
        }
        libError?.let {
            fail(it)
            return
        }
        ensureChannel()
        startForeground(1, notification("connecting…"))
        connecting = true
        lastError = ""

        val server = intent.getStringExtra("server")?.trim()
        val port = intent.getIntExtra("port", 25565)
        val token = intent.getStringExtra("token")?.trim()
        if (server.isNullOrEmpty() || token.isNullOrEmpty()) {
            fail("missing server/token")
            return
        }

        Thread {
            try {
                connectAndRun(server, port, token)
            } catch (t: Throwable) {
                // Any exception in this thread used to crash the whole app.
                fail("${t.javaClass.simpleName}: ${t.message}")
            }
        }.start()
    }

    private fun connectAndRun(server: String, port: Int, token: String) {
        val cfg = JSONObject(nativeConnect(server, port, token))
        if (!cfg.optBoolean("ok", false)) {
            fail(cfg.optString("error", "connection failed"))
            return
        }
        lastIp = cfg.getString("ip")

        val builder = Builder()
            .setSession("mcvpn")
            .setMtu(cfg.getInt("mtu"))
            .addAddress(cfg.getString("ip"), cfg.getInt("prefix_len"))
            .addRoute("0.0.0.0", 0)
            // Deliberately NO IPv6 route: per VpnService.Builder docs, a family
            // with no address/route/DNS is blocked by the OS instantly, and an
            // IPv4-only tunnel with a "::/0" route instead blackholes every
            // IPv6 connection through the tunnel (apps stall until fallback).
            // Blocked-fast is the standard single-family VPN behavior.

        val dns = cfg.optJSONArray("dns")
        if (dns != null) {
            for (i in 0 until dns.length()) {
                builder.addDnsServer(dns.getString(i))
            }
        }
        // Keep this app's own traffic (the tunnel's TCP socket) on the
        // physical network: no routing loop, safe reconnects.
        try {
            builder.addDisallowedApplication(packageName)
        } catch (_: Exception) {
        }

        val pfd: ParcelFileDescriptor? = builder.establish()
        if (pfd == null) {
            // Also releases `connecting` (it used to stay true forever, which
            // made the Connect button unusable until the app was force-stopped).
            fail("VPN permission missing or revoked (establish() returned null)")
            return
        }
        val fd = pfd.detachFd()
        if (!nativeStart(fd)) {
            fail("tunnel start failed")
            return
        }
        connecting = false
        running = true
        connectedAtMs = SystemClock.elapsedRealtime()
        refreshLog()

        var tick = 0
        while (running) {
            val stats = JSONObject(nativeGetStats())
            lastStats = stats.toString()
            // Tunnel ended (server closed / network died): say WHY instead of a
            // silent flip back to "idle".
            if (stats.optString("state") != "connected") {
                val why = stats.optString("error", "")
                fail(if (why.isEmpty()) "connection closed" else "connection lost: $why")
                return
            }
            val nm = getSystemService(NOTIFICATION_SERVICE) as NotificationManager
            val up = stats.optLong("up", 0) / 1024
            val down = stats.optLong("down", 0) / 1024
            nm.notify(1, notification("up ${up} KB · down ${down} KB"))
            if (tick++ % 3 == 0) {
                refreshLog()
            }
            Thread.sleep(1000)
        }
    }

    private fun stopVpn() {
        // Unconditional: nativeStop is idempotent, and a half-established
        // session (connected, VPN not yet up) must be closed too.
        try {
            nativeStop()
        } catch (_: Throwable) {
        }
        running = false
        connecting = false
        lastIp = ""
        connectedAtMs = 0L
        try {
            stopForeground(STOP_FOREGROUND_REMOVE)
        } catch (_: Throwable) {
        }
        stopSelf()
    }

    private fun ensureChannel() {
        val nm = getSystemService(NOTIFICATION_SERVICE) as NotificationManager
        if (nm.getNotificationChannel(CHANNEL_ID) == null) {
            nm.createNotificationChannel(
                NotificationChannel(CHANNEL_ID, "mcvpn tunnel", NotificationManager.IMPORTANCE_LOW)
            )
        }
    }

    private fun notification(text: String): Notification {
        val pi = PendingIntent.getActivity(
            this, 0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE
        )
        return Notification.Builder(this, CHANNEL_ID)
            .setContentTitle("mcvpn")
            .setContentText(text)
            .setSmallIcon(R.drawable.ic_stat)
            .setContentIntent(pi)
            .setOngoing(true)
            .build()
    }
}
