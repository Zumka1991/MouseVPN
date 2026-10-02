package dev.mousevpn.app

import android.content.Intent
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.os.SystemClock
import android.os.Handler
import android.os.Looper
import android.util.Log
import org.json.JSONObject
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.Executors
import java.util.concurrent.Future
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

class MouseVpnService : VpnService() {
    private val executor = Executors.newSingleThreadExecutor()
    private val stopExecutor = Executors.newSingleThreadExecutor()
    private val networkHandler = Handler(Looper.getMainLooper())
    private var task: Future<*>? = null
    @Volatile private var stopRequested = false
    private val connectionGeneration = AtomicLong()
    private val networkRestartRequested = AtomicBoolean()
    @Volatile private var handle = 0L
    @Volatile private var diagnosticSessionId = 0L
    @Volatile private var underlyingNetwork = "unknown"
    private val underlyingNetworks = ConcurrentHashMap<Network, UnderlyingNetworkState>()
    private var selectedUnderlyingNetwork: Network? = null
    private var selectedUnderlyingState: UnderlyingNetworkState? = null
    private lateinit var diagnostics: DiagnosticStore
    private var lastCheckpointElapsedRealtime = 0L
    private val networkCallback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) {
            if (updateUnderlyingNetwork(network)) signalNetworkChange()
        }

        override fun onCapabilitiesChanged(network: Network, capabilities: NetworkCapabilities) {
            if (updateUnderlyingNetwork(network, capabilities)) signalNetworkChange()
        }

        override fun onLost(network: Network) {
            underlyingNetworks.remove(network)
            if (refreshUnderlyingNetwork()) signalNetworkChange()
        }
    }
    private val signalNetworkChange = Runnable {
        if (handle != 0L) {
            networkRestartRequested.set(true)
            Log.i(LOG_TAG, "physical network changed to $underlyingNetwork; rebuilding VPN")
        }
    }

    override fun onCreate() {
        super.onCreate()
        diagnostics = DiagnosticStore(this)
        val connectivity = getSystemService(ConnectivityManager::class.java)
        // Seed every physical route synchronously. `activeNetwork` may itself be
        // another VPN, and binding MouseVPN's transport socket to it is rejected
        // by some Android vendors before the callback delivers the real route.
        @Suppress("DEPRECATION")
        val availableNetworks = connectivity.allNetworks
        availableNetworks.forEach { network ->
            connectivity.getNetworkCapabilities(network)?.let { capabilities ->
                updateUnderlyingNetwork(network, capabilities)
            }
        }
        val request = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            .build()
        connectivity.registerNetworkCallback(request, networkCallback)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_DISCONNECT) {
            disconnect()
            return START_NOT_STICKY
        }
        startForeground(VpnNotification.ID, VpnNotification.create(this, STATUS_CONNECTING))
        if (task?.isDone != false) {
            stopRequested = false
            val generation = connectionGeneration.incrementAndGet()
            task = executor.submit { runConnectionLoop(generation) }
        }
        return START_STICKY
    }

    private fun runConnectionLoop(generation: Long) {
        val backoff = ReconnectBackoff()
        val initialBudget = InitialConnectBudget(MAX_INITIAL_CONNECT_ATTEMPTS)
        while (isAttemptActive(generation)) {
            val selected = ProfileStore(this).selected()
            if (selected?.accountId != null && !AccountManager(this).allowed(selected)) {
                showFinalConnectionError("Подписка истекла или доступ отключён. Откройте аккаунт.", 1)
                return
            }
            val result = connectOnce(generation)
            if (!isAttemptActive(generation) || result.outcome == AttemptOutcome.STOPPED) {
                return
            }
            if (result.connectedForMs > 0L) initialBudget.recordConnected()
            if (result.outcome == AttemptOutcome.SETUP_FAILED && initialBudget.recordFailure()) {
                showFinalConnectionError(result.detail, initialBudget.failures)
                return
            }
            if (result.connectedForMs >= RECONNECT_BACKOFF_RESET_MS) backoff.reset()
            val delay = when (result.outcome) {
                AttemptOutcome.PARAMETERS_CHANGED,
                AttemptOutcome.NETWORK_CHANGED,
                -> 0L
                else -> backoff.nextDelayMs()
            }
            if (delay > 0L) {
                val status = if (result.outcome == AttemptOutcome.SETUP_FAILED) {
                    buildString {
                        append(STATUS_CONNECTING)
                        append(' ')
                        append(result.detail ?: "Неизвестная ошибка")
                        append(". Повтор через ${delay / 1_000} с")
                        if (!initialBudget.connected) {
                            append(" (попытка ${initialBudget.failures + 1}")
                            append(" из $MAX_INITIAL_CONNECT_ATTEMPTS)")
                        }
                    }
                } else {
                    "$STATUS_CONNECTING Повтор через ${delay / 1_000} с"
                }
                broadcast(status)
                getSystemService(android.app.NotificationManager::class.java)
                    .notify(VpnNotification.ID, VpnNotification.create(this, status))
            }
            if (!waitForRetry(delay, generation)) return
        }
    }

    private fun connectOnce(generation: Long): AttemptResult {
        var descriptor: ParcelFileDescriptor? = null
        var connectedAt = 0L
        try {
            ensureAttemptActive(generation)
            // This attempt will bind its outer socket to the currently selected
            // physical network. A later callback sets the flag again if the route
            // changes while setup is in flight.
            networkRestartRequested.set(false)
            broadcast(STATUS_CONNECTING)
            val profile = requireNotNull(ProfileStore(this).selected()) { "Сначала вставьте профиль" }
            diagnosticSessionId = runCatching {
                diagnostics.begin(profile, underlyingNetwork)
            }.getOrDefault(0L)
            lastCheckpointElapsedRealtime = SystemClock.elapsedRealtime()
            val prepared = JSONObject(
                NativeBridge.prepare(
                    this,
                    profile.endpoint,
                    profile.serverPublicKey,
                    profile.clientPrivateKey,
                    profile.protocol.nativeValue,
                    generation,
                ),
            )
            handle = prepared.getLong("handle")
            ensureAttemptActive(generation)
            val serverMtu = prepared.getInt("mtu")
            val mtu = calculateTunnelMtu(
                serverMtu,
                underlyingMtu(),
                profile.protocol != VpnProtocol.LEGACY,
            )
            val builder = Builder()
                .setSession("MouseVPN")
                .setMtu(mtu)
                .addAddress(prepared.getString("address"), prepared.getInt("prefix"))
                .addRoute("0.0.0.0", 0)
                .addDnsServer(prepared.getString("dns"))
                .setBlocking(true)
            val appPolicy = applyAppPolicy(builder)
            descriptor = builder.establish()
            requireNotNull(descriptor) { "Android не создал VPN-интерфейс" }
            ensureAttemptActive(generation)
            val fd = descriptor.detachFd()
            descriptor = null
            check(NativeBridge.start(handle, fd)) { "Rust-ядро не запустило туннель" }
            connectedAt = SystemClock.elapsedRealtime()
            connectedSinceElapsedRealtime = connectedAt
            if (diagnosticSessionId != 0L) {
                runCatching { diagnostics.connected(diagnosticSessionId, underlyingNetwork) }
            }
            val summary = buildString {
                append("Подключено: ${if (profile.accountId != null) profile.name else profile.endpoint}")
                if (appPolicy.second > 0) {
                    append(
                        if (appPolicy.first == AppRoutingMode.EXCLUDE) " (в обход: ${appPolicy.second})"
                        else " (через VPN: ${appPolicy.second})",
                    )
                }
                // Only worth showing when it differs from what the server asked
                // for, because then it is the answer to "why is this slow here".
                if (mtu != serverMtu) append(" (MTU $mtu)")
            }
            broadcast(summary)
            val notification = VpnNotification.create(this, summary)
            getSystemService(android.app.NotificationManager::class.java)
                .notify(VpnNotification.ID, notification)
            return monitor(handle, connectedAt, summary, profile)
        } catch (_: InterruptedException) {
            val current = handle
            if (current != 0L) NativeBridge.stop(current)
            handle = 0L
            connectedSinceElapsedRealtime = 0L
            return AttemptResult(AttemptOutcome.STOPPED, elapsedSince(connectedAt))
        } catch (error: Exception) {
            if (!isAttemptActive(generation)) return AttemptResult(AttemptOutcome.STOPPED, elapsedSince(connectedAt))
            val detail = connectionErrorDetail(error.message)
            finishDiagnostics(
                "connection_error",
                detail,
                handle,
            )
            if (handle != 0L) NativeBridge.stop(handle)
            handle = 0L
            connectedSinceElapsedRealtime = 0L
            return AttemptResult(
                AttemptOutcome.SETUP_FAILED,
                connectedForMs = elapsedSince(connectedAt),
                detail = detail,
            )
        } finally {
            descriptor?.close()
        }
    }

    private fun waitForRetry(delayMs: Long, generation: Long): Boolean {
        if (delayMs == 0L) return isAttemptActive(generation)
        return try {
            Thread.sleep(delayMs)
            isAttemptActive(generation)
        } catch (_: InterruptedException) {
            Thread.currentThread().interrupt()
            false
        }
    }

    private fun showFinalConnectionError(detail: String?, attempts: Int) {
        val status = buildString {
            append("Ошибка подключения: ")
            append(detail ?: "Не удалось связаться с сервером")
            append(" ($attempts попытки)")
        }
        broadcast(status)
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private fun isAttemptActive(generation: Long): Boolean =
        !stopRequested &&
            !Thread.currentThread().isInterrupted &&
            connectionGeneration.get() == generation

    private fun ensureAttemptActive(generation: Long) {
        if (!isAttemptActive(generation)) throw InterruptedException()
    }

    // Called from the native handshake on the connection worker thread.
    fun isConnectionCancelled(generation: Long): Boolean = !isAttemptActive(generation)

    /**
     * MTU of the network carrying the tunnel, or null when it is unknown.
     *
     * Use the physical network selected for bindSocket. activeNetwork can
     * still be a VPN during reconnect and report the old tunnel's MTU.
     *
     * Android only exposes the link MTU from API 29; on anything older the
     * tunnel keeps the value the server negotiated.
     */
    private fun underlyingMtu(): Int? {
        if (Build.VERSION.SDK_INT < 29) return null
        val manager = getSystemService(ConnectivityManager::class.java)
        val network = synchronized(this) { selectedUnderlyingNetwork } ?: return null
        val mtu = manager.getLinkProperties(network)?.mtu ?: return null
        return mtu.takeIf { it > 0 }
    }

    /**
     * Applies the selected allowlist or denylist and returns how many entries worked.
     *
     * A package that has since been uninstalled must never prevent the tunnel
     * from coming up, so each entry is applied on its own and a failure only
     * drops that one app.
     *
     * Failed entries are deliberately left in the store. An app can be missing
     * for reasons that pass — an update in flight, a profile not yet unlocked —
     * and silently discarding a choice the user made is worse than carrying an
     * entry that costs one failed call per connection.
     */
    private fun applyAppPolicy(builder: Builder): Pair<AppRoutingMode, Int> {
        val policy = ExcludedApps(this).policy()
        var applied = 0
        policy.packages.filterNot { it == packageName }.forEach { selectedPackage ->
            runCatching {
                if (policy.mode == AppRoutingMode.EXCLUDE) {
                    builder.addDisallowedApplication(selectedPackage)
                } else {
                    builder.addAllowedApplication(selectedPackage)
                }
            }
                .onSuccess { applied++ }
        }
        // Keep the app itself on the TUN in allowlist mode so its explicit
        // connectivity test measures the VPN path. The transport UDP socket is
        // still the only socket protected from the VPN by VpnService.protect().
        if (policy.mode == AppRoutingMode.INCLUDE) {
            builder.addAllowedApplication(packageName)
        }
        return policy.mode to applied
    }

    private fun monitor(currentHandle: Long, connectedAt: Long, connectedSummary: String, profile: VpnProfile): AttemptResult {
        var reconnectingShown = false
        while (!Thread.currentThread().isInterrupted && handle == currentHandle) {
            if (profile.accountId != null && !AccountManager(this).allowed(profile)) {
                NativeBridge.stop(currentHandle)
                handle = 0L
                connectedSinceElapsedRealtime = 0L
                finishDiagnostics("access_expired", null, currentHandle)
                showFinalConnectionError("Подписка истекла или доступ отключён. Откройте аккаунт.", 1)
                return AttemptResult(AttemptOutcome.STOPPED, elapsedSince(connectedAt))
            }
            if (networkRestartRequested.getAndSet(false)) {
                val status = "Смена сети… обновление VPN"
                broadcast(status)
                getSystemService(android.app.NotificationManager::class.java)
                    .notify(VpnNotification.ID, VpnNotification.create(this, status))
                finishDiagnostics("network_changed", null, currentHandle)
                NativeBridge.stop(currentHandle)
                if (handle == currentHandle) handle = 0L
                connectedSinceElapsedRealtime = 0L
                return AttemptResult(
                    AttemptOutcome.NETWORK_CHANGED,
                    connectedForMs = elapsedSince(connectedAt),
                )
            }
            val nativeStatus = NativeBridge.status(currentHandle)
            if (applicationInfo.flags and android.content.pm.ApplicationInfo.FLAG_DEBUGGABLE != 0) {
                Log.d("MouseVPNMetrics", NativeBridge.metrics(currentHandle))
            }
            if (nativeStatus == "parameters-changed") {
                finishDiagnostics("parameters_changed", null, currentHandle)
                NativeBridge.stop(currentHandle)
                handle = 0L
                connectedSinceElapsedRealtime = 0L
                return AttemptResult(
                    AttemptOutcome.PARAMETERS_CHANGED,
                    connectedForMs = elapsedSince(connectedAt),
                )
            }
            if (nativeStatus == "reconnecting") {
                if (!reconnectingShown) {
                    val status = "Смена сети… переподключение"
                    broadcast(status)
                    getSystemService(android.app.NotificationManager::class.java)
                        .notify(VpnNotification.ID, VpnNotification.create(this, status))
                    reconnectingShown = true
                }
            } else if (nativeStatus != "running") {
                finishDiagnostics("connection_lost", nativeStatus, currentHandle)
                NativeBridge.stop(currentHandle)
                handle = 0L
                connectedSinceElapsedRealtime = 0L
                return AttemptResult(
                    AttemptOutcome.CONNECTION_LOST,
                    connectedForMs = elapsedSince(connectedAt),
                )
            } else if (reconnectingShown) {
                broadcast(connectedSummary)
                getSystemService(android.app.NotificationManager::class.java)
                    .notify(
                        VpnNotification.ID,
                        VpnNotification.create(this, connectedSummary),
                    )
                reconnectingShown = false
            }
            val now = SystemClock.elapsedRealtime()
            if (now - lastCheckpointElapsedRealtime >= DIAGNOSTIC_CHECKPOINT_MS) {
                val sessionId = diagnosticSessionId
                if (sessionId != 0L) {
                    runCatching {
                        diagnostics.checkpoint(
                            sessionId,
                            readMetrics(currentHandle),
                            underlyingNetwork,
                        )
                    }
                }
                lastCheckpointElapsedRealtime = now
            }
            try {
                Thread.sleep(1_000)
            } catch (_: InterruptedException) {
                Thread.currentThread().interrupt()
                return AttemptResult(AttemptOutcome.STOPPED, elapsedSince(connectedAt))
            }
        }
        return AttemptResult(AttemptOutcome.STOPPED, elapsedSince(connectedAt))
    }

    private fun elapsedSince(startedAt: Long): Long =
        if (startedAt == 0L) 0L else (SystemClock.elapsedRealtime() - startedAt).coerceAtLeast(0L)

    private fun disconnect() {
        stopRequested = true
        connectionGeneration.incrementAndGet()
        val current = handle
        finishDiagnostics("user_disconnect", null, current)
        handle = 0L
        connectedSinceElapsedRealtime = 0L
        stopNativeAsync(current)
        task?.cancel(true)
        task = null
        broadcast("Отключено")
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private fun broadcast(status: String) {
        currentStatus = status
        sendBroadcast(
            Intent(ACTION_STATUS)
                .setPackage(packageName)
                .putExtra(EXTRA_STATUS, status),
        )
    }

    private fun signalNetworkChange() {
        networkHandler.removeCallbacks(signalNetworkChange)
        networkHandler.postDelayed(signalNetworkChange, NETWORK_CHANGE_DEBOUNCE_MS)
    }

    /**
     * Excludes a native UDP socket from the VPN and pins it to the physical
     * network selected by the connectivity callback.
     *
     * `protect` alone only prevents a routing loop. After Wi-Fi/mobile roaming,
     * Android may otherwise keep a newly created socket on the obsolete route.
     * Rust calls this method before connecting every handshake or migration
     * socket, so a failed race with a disappearing network is retried safely.
     */
    fun protectAndBindSocket(socketFd: Int): Boolean {
        if (!protect(socketFd)) {
            Log.e(LOG_TAG, "VpnService.protect rejected UDP socket $socketFd")
            return false
        }
        val network = synchronized(this) { selectedUnderlyingNetwork } ?: return true
        return try {
            ParcelFileDescriptor.fromFd(socketFd).use { descriptor ->
                network.bindSocket(descriptor.fileDescriptor)
            }
            true
        } catch (error: Exception) {
            // `protect` prevents a VPN routing loop. Binding merely pins that
            // protected socket to the preferred physical route. Some vendor
            // firmwares reject bindSocket during transitions; the system's
            // physical default route remains a safe fallback.
            Log.w(LOG_TAG, "Unable to bind protected UDP socket; using default route", error)
            true
        }
    }

    private fun updateUnderlyingNetwork(network: Network): Boolean {
        val capabilities = getSystemService(ConnectivityManager::class.java)
            .getNetworkCapabilities(network)
        return if (capabilities != null) {
            updateUnderlyingNetwork(network, capabilities)
        } else {
            underlyingNetworks.remove(network)
            refreshUnderlyingNetwork()
        }
    }

    private fun updateUnderlyingNetwork(
        network: Network,
        capabilities: NetworkCapabilities,
    ): Boolean {
        if (isPhysicalInternet(capabilities)) {
            underlyingNetworks[network] = networkState(capabilities)
        } else {
            underlyingNetworks.remove(network)
        }
        return refreshUnderlyingNetwork()
    }

    private fun isPhysicalInternet(capabilities: NetworkCapabilities): Boolean =
        capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
            capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)

    @Synchronized
    private fun refreshUnderlyingNetwork(): Boolean {
        val previousNetwork = selectedUnderlyingNetwork
        val previousState = selectedUnderlyingState
        val highestPriority = underlyingNetworks.values.maxOfOrNull(::networkPriority)
        val current = previousNetwork?.takeIf { network ->
            underlyingNetworks[network]?.let(::networkPriority) == highestPriority
        }
        selectedUnderlyingNetwork = current ?: underlyingNetworks.entries
            .firstOrNull { networkPriority(it.value) == highestPriority }
            ?.key
        selectedUnderlyingState = selectedUnderlyingNetwork?.let(underlyingNetworks::get)
        underlyingNetwork = selectedUnderlyingState?.diagnosticLabel ?: "none"
        val networkChanged = selectedUnderlyingNetwork != previousNetwork
        val stateChanged = selectedUnderlyingState != previousState
        if (networkChanged || stateChanged) {
            runCatching {
                setUnderlyingNetworks(selectedUnderlyingNetwork?.let { arrayOf(it) })
            }
        }
        // Capability updates (most often VALIDATED toggling) do not invalidate
        // a socket already bound to this Network. Only an identity change means
        // Wi-Fi/cellular roaming and requires native socket migration.
        return networkChanged
    }

    private fun networkPriority(network: UnderlyingNetworkState): Int =
        (if (network.validated) 10 else 0) + when (network.transport) {
            "ethernet" -> 3
            "wifi" -> 2
            "cellular" -> 1
            else -> 0
        }

    private fun networkState(capabilities: NetworkCapabilities) = UnderlyingNetworkState(
        transport = when {
            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> "ethernet"
            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> "wifi"
            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> "cellular"
            else -> "other"
        },
        validated = capabilities.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED),
    )

    private fun readMetrics(currentHandle: Long): DiagnosticMetrics =
        if (currentHandle == 0L) DiagnosticMetrics()
        else runCatching { DiagnosticMetrics.parse(NativeBridge.metrics(currentHandle)) }
            .getOrDefault(DiagnosticMetrics())

    @Synchronized
    private fun finishDiagnostics(outcome: String, detail: String?, currentHandle: Long) {
        val sessionId = diagnosticSessionId
        if (sessionId == 0L) return
        diagnosticSessionId = 0L
        runCatching {
            diagnostics.finish(
                sessionId,
                outcome,
                detail,
                readMetrics(currentHandle),
                underlyingNetwork,
            )
        }
    }

    private fun stopNativeAsync(current: Long) {
        if (current != 0L) stopExecutor.execute { NativeBridge.stop(current) }
    }

    override fun onRevoke() {
        disconnect()
        super.onRevoke()
    }

    override fun onDestroy() {
        stopRequested = true
        connectionGeneration.incrementAndGet()
        task?.cancel(true)
        val current = handle
        finishDiagnostics("service_destroyed", null, current)
        handle = 0L
        connectedSinceElapsedRealtime = 0L
        networkHandler.removeCallbacks(signalNetworkChange)
        stopNativeAsync(current)
        runCatching {
            getSystemService(ConnectivityManager::class.java)
                .unregisterNetworkCallback(networkCallback)
        }
        executor.shutdownNow()
        stopExecutor.shutdown()
        super.onDestroy()
    }

    companion object {
        @Volatile
        var currentStatus: String = "Отключено"
            private set

        @Volatile
        var connectedSinceElapsedRealtime: Long = 0L
            private set

        private const val NETWORK_CHANGE_DEBOUNCE_MS = 400L
        private const val DIAGNOSTIC_CHECKPOINT_MS = 60_000L
        private const val RECONNECT_BACKOFF_RESET_MS = 60_000L
        private const val MAX_INITIAL_CONNECT_ATTEMPTS = 3
        private const val LOG_TAG = "MouseVpnService"

        const val STATUS_CONNECTING = "Подключение…"

        const val ACTION_CONNECT = "dev.mousevpn.app.CONNECT"
        const val ACTION_DISCONNECT = "dev.mousevpn.app.DISCONNECT"
        const val ACTION_STATUS = "dev.mousevpn.app.STATUS"
        const val EXTRA_STATUS = "status"
    }

    private data class UnderlyingNetworkState(
        val transport: String,
        val validated: Boolean,
    ) {
        val diagnosticLabel: String
            get() = if (validated) transport else "$transport-unvalidated"
    }

    private data class AttemptResult(
        val outcome: AttemptOutcome,
        val connectedForMs: Long,
        val detail: String? = null,
    )

    private enum class AttemptOutcome {
        SETUP_FAILED,
        CONNECTION_LOST,
        PARAMETERS_CHANGED,
        NETWORK_CHANGED,
        STOPPED,
    }

    private class ReconnectBackoff {
        private var nextMs = 1_000L

        fun nextDelayMs(): Long = nextMs.also { nextMs = (nextMs * 2).coerceAtMost(16_000L) }

        fun reset() {
            nextMs = 1_000L
        }
    }
}
