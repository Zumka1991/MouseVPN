package dev.mousevpn.app

import android.content.Context
import android.os.Build
import org.json.JSONObject
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URI
import java.net.URL

class AccountManager(context: Context) {
    private val store = ProfileStore(context.applicationContext)

    fun state(): JSONObject? = store.accountState()
    fun signedIn(): Boolean = state()?.optString("token")?.isNotBlank() == true

    fun signIn(base: String, login: String, password: String): JSONObject = synchronized(lock) {
        var service = validateBase(base)
        val credentials = JSONObject().put("login", login).put("password", password)
        val response = try {
            request(service, "/v1/login", "POST", null, credentials)
        } catch (error: IOException) {
            // Only the configured, same-owner service may receive credentials on failover.
            // Other POST requests are not replayed: a lost response must not duplicate a ticket.
            val fallback = BuildConfig.ACCOUNT_FALLBACK_URL
            if (fallback.isBlank() || service != BuildConfig.ACCOUNT_SERVICE_URL.trimEnd('/')) throw error
            service = validateBase(fallback)
            request(service, "/v1/login", "POST", null, credentials)
        }
        val account = response.getJSONObject("account")
        val previous = state()
        val keys = if (previous != null && previous.optString("base") == service && previous.optString("user_id") == account.getString("id")) {
            previous
        } else JSONObject(NativeBridge.generateDeviceKeys())
        val saved = JSONObject()
            .put("base", service).put("token", response.getString("token"))
            .put("user_id", account.getString("id")).put("login", account.getString("login"))
            .put("private_key", keys.getString("private_key")).put("public_key", keys.getString("public_key"))
            .put("account", account)
        // Persist before enrollment: a lost HTTP response must not orphan a key
        // and consume a second device slot on the next login.
        store.saveAccountState(saved)
        val enrolled = request(service, "/v1/account/devices", "POST", saved.getString("token"),
            JSONObject().put("name", Build.MODEL.take(60).ifBlank { "Android" })
                .put("platform", "android").put("public_key", saved.getString("public_key")))
        apply(saved, enrolled)
    }

    fun refresh(): JSONObject = synchronized(lock) {
        val saved = state() ?: error("Войдите в аккаунт")
        require(saved.optString("token").isNotBlank()) { "Войдите в аккаунт" }
        apply(saved, request(saved.getString("base"), "/v1/account", "GET", saved.getString("token")))
    }

    fun revoke(deviceId: String): JSONObject = synchronized(lock) {
        require(deviceId.matches(Regex("[a-fA-F0-9-]{36}"))) { "Неверное устройство" }
        val saved = state() ?: error("Войдите в аккаунт")
        apply(saved, request(saved.getString("base"), "/v1/account/devices/$deviceId", "DELETE", saved.getString("token")))
    }

    fun logout() = synchronized(lock) {
        state()?.let { saved ->
            runCatching { request(saved.getString("base"), "/v1/logout", "POST", saved.getString("token")) }
            saved.put("token", "")
            store.saveAccountState(saved)
        }
        store.replaceAccountProfiles(emptyList())
    }

    fun allowed(profile: VpnProfile): Boolean {
        if (profile.accountId == null) return true
        val saved = state() ?: return false
        if (saved.optString("token").isBlank() || saved.optString("user_id") != profile.accountId) return false
        val account = saved.optJSONObject("account") ?: return false
        if (!account.optBoolean("active") || account.optLong("valid_until") <= System.currentTimeMillis() / 1000) return false
        val devices = account.getJSONArray("devices")
        if ((0 until devices.length()).none { devices.getJSONObject(it).getString("public_key") == saved.getString("public_key") }) return false
        val servers = account.getJSONArray("servers")
        return (0 until servers.length()).any { servers.getJSONObject(it).getString("id") == profile.serverId }
    }

    fun billing(): JSONObject = synchronized(lock) {
        val saved = state() ?: error("Войдите в аккаунт")
        request(saved.getString("base"), "/v1/account/billing", "GET", saved.getString("token"))
    }
    fun requestPayment(id: String, months: Int, note: String, revision: Long): JSONObject = synchronized(lock) {
        val saved = state() ?: error("Войдите в аккаунт")
        request(saved.getString("base"), "/v1/account/payment-requests", "POST", saved.getString("token"), JSONObject().put("id",id).put("months",months).put("note",note).put("details_revision",revision))
    }
    fun serverLoad(profile: VpnProfile): String {
        if (profile.accountId == null) return profile.endpoint
        val servers = state()?.optJSONObject("account")?.optJSONArray("servers")
        if (servers != null) for (i in 0 until servers.length()) {
            val s = servers.getJSONObject(i)
            if (s.optString("id") == profile.serverId) return serverLoad(s)
        }
        return "Онлайн: нет свежих данных"
    }
    fun serverLoad(server: JSONObject): String {
        val age = System.currentTimeMillis() / 1000 - server.optLong("online_updated_at")
        return if (!server.isNull("online_devices") && age in 0..90) "${server.getInt("online_devices")} устройств онлайн" else "Онлайн: нет свежих данных"
    }

    fun tickets(): org.json.JSONArray = synchronized(lock) {
        val saved = state() ?: error("Войдите в аккаунт")
        org.json.JSONArray(requestText(saved.getString("base"), "/v1/account/tickets", "GET", saved.getString("token")))
    }

    fun createTicket(subject: String, text: String): JSONObject = synchronized(lock) {
        val saved = state() ?: error("Войдите в аккаунт")
        request(saved.getString("base"), "/v1/account/tickets", "POST", saved.getString("token"),
            JSONObject().put("subject", subject).put("text", text))
    }

    fun ticket(id: String, before: Long? = null): JSONObject = synchronized(lock) {
        require(id.matches(Regex("[a-fA-F0-9-]{36}"))) { "Неверное обращение" }
        val saved = state() ?: error("Войдите в аккаунт")
        request(saved.getString("base"), "/v1/account/tickets/$id" + (before?.let { "?before=$it" } ?: ""), "GET", saved.getString("token"))
    }

    fun reply(id: String, text: String): JSONObject = synchronized(lock) {
        require(id.matches(Regex("[a-fA-F0-9-]{36}"))) { "Неверное обращение" }
        val saved = state() ?: error("Войдите в аккаунт")
        request(saved.getString("base"), "/v1/account/tickets/$id/messages", "POST", saved.getString("token"), JSONObject().put("text", text))
    }

    private fun apply(saved: JSONObject, account: JSONObject): JSONObject {
        saved.put("account", account)
        store.saveAccountState(saved)
        val devices = account.getJSONArray("devices")
        val registered = (0 until devices.length()).any {
            devices.getJSONObject(it).getString("public_key") == saved.getString("public_key")
        }
        val servers = account.getJSONArray("servers")
        val profiles = if (registered && account.getBoolean("active")) (0 until servers.length()).map { index ->
            val server = servers.getJSONObject(index)
            VpnProfile(
                id = server.getString("id"), name = server.getString("name"),
                endpoint = server.getString("endpoint"), serverPublicKey = server.getString("public_key"),
                clientPrivateKey = saved.getString("private_key"),
                protocol = store.accountProtocol(),
                accountId = account.getString("id"), serverId = server.getString("id"),
                validUntil = account.getLong("valid_until"),
            ).validate()
        } else emptyList()
        store.replaceAccountProfiles(profiles)
        return account
    }

    private fun request(base: String, path: String, method: String, token: String?, body: JSONObject? = null): JSONObject {
        return JSONObject(requestText(base, path, method, token, body))
    }

    private fun requestText(base: String, path: String, method: String, token: String?, body: JSONObject? = null): String {
        val connection = URL(validateBase(base) + path).openConnection() as HttpURLConnection
        return try {
            connection.requestMethod = method
            connection.connectTimeout = 7_000
            connection.readTimeout = 15_000
            connection.instanceFollowRedirects = false
            connection.setRequestProperty("Accept", "application/json")
            if (!token.isNullOrBlank()) connection.setRequestProperty("Authorization", "Bearer $token")
            if (body != null) {
                connection.doOutput = true
                connection.setRequestProperty("Content-Type", "application/json")
                connection.outputStream.use { it.write(body.toString().toByteArray(Charsets.UTF_8)) }
            }
            val status = connection.responseCode
            val stream = if (status in 200..299) connection.inputStream else connection.errorStream
            val bytes = stream?.use { source ->
                val output = java.io.ByteArrayOutputStream()
                val buffer = ByteArray(8192)
                while (true) {
                    val length = source.read(buffer)
                    if (length < 0) break
                    require(output.size() + length <= 1_048_576) { "Слишком большой ответ сервиса" }
                    output.write(buffer, 0, length)
                }
                output.toByteArray()
            } ?: ByteArray(0)
            require(bytes.size <= 1_048_576) { "Слишком большой ответ сервиса" }
            val response = bytes.toString(Charsets.UTF_8)
            require(status in 200..299) { runCatching { JSONObject(response).optString("error", "Запрос отклонён") }.getOrDefault("Сервис недоступен") }
            response
        } catch (error: IOException) {
            throw IOException("Не удалось связаться с сервисом. Проверьте интернет и попробуйте снова.", error)
        } finally { connection.disconnect() }
    }

    companion object {
        private val lock = Any()
        fun validateBase(value: String): String {
            val uri = URI(value.trim())
            require(uri.scheme == "https" && !uri.host.isNullOrBlank() && uri.userInfo == null &&
                uri.query == null && uri.fragment == null && (uri.path.isNullOrBlank() || uri.path.matches(Regex("[A-Za-z0-9/_-]*")))) {
                "Введите адрес сервиса HTTPS, например https://vpn.example.ru"
            }
            return uri.toString().trimEnd('/')
        }
    }
}
