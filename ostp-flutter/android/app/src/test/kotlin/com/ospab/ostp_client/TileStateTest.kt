package com.ospab.ostp_client

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/** The tile's state mapping and the service's "the core has stopped" rule (plain JVM). */
class TileStateTest {

    private fun view(running: Boolean, starting: Boolean, link: Int, hasConfig: Boolean = true, profile: String? = "Home") =
        OstpTileService.tileView(running, starting, link, hasConfig, profile)

    @Test
    fun connectedOnlyWhenTheServerAnswered() {
        assertEquals(OstpTileService.TileView(true, "Home"), view(running = true, starting = false, link = 2))
        assertEquals(OstpTileService.TileView(true, "Connected"), view(running = true, starting = false, link = 2, profile = null))
        // The core runs but the handshake (or a reconnect) is not done.
        assertEquals(OstpTileService.TileView(true, "Connecting…"), view(running = true, starting = false, link = 1))
        assertEquals(OstpTileService.TileView(true, "Connecting…"), view(running = true, starting = false, link = 0))
    }

    @Test
    fun startingShowsConnecting() {
        assertEquals(OstpTileService.TileView(true, "Connecting…"), view(running = false, starting = true, link = 0))
    }

    @Test
    fun offStates() {
        assertEquals(OstpTileService.TileView(false, "Home"), view(running = false, starting = false, link = 0))
        assertEquals(OstpTileService.TileView(false, "Off"), view(running = false, starting = false, link = 0, profile = null))
        assertEquals(OstpTileService.TileView(false, "No profile"), view(running = false, starting = false, link = 0, hasConfig = false, profile = null))
    }

    @Test
    fun coreGoneAfterBeingUp() {
        assertFalse(OstpVpnService.coreGone(everUp = true, zeroForMs = 0, sinceStartMs = 60_000))
        assertFalse(OstpVpnService.coreGone(everUp = true, zeroForMs = OstpVpnService.CORE_GONE_AFTER_UP_MS - 1, sinceStartMs = 60_000))
        assertTrue(OstpVpnService.coreGone(everUp = true, zeroForMs = OstpVpnService.CORE_GONE_AFTER_UP_MS, sinceStartMs = 60_000))
    }

    @Test
    fun coreSilentAtStart() {
        // Zero right after the start is normal: the core gets time to report.
        assertFalse(OstpVpnService.coreGone(everUp = false, zeroForMs = 10_000, sinceStartMs = 10_000))
        assertFalse(OstpVpnService.coreGone(everUp = false, zeroForMs = 20_000, sinceStartMs = OstpVpnService.CORE_SILENT_AT_START_MS - 1))
        assertTrue(OstpVpnService.coreGone(everUp = false, zeroForMs = 0, sinceStartMs = OstpVpnService.CORE_SILENT_AT_START_MS))
    }
}
