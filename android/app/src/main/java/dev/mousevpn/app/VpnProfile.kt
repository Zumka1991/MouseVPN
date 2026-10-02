package dev.mousevpn.app

import android.util.Base64
import org.json.JSONObject
import java.util.UUID

enum class VpnProtocol(val nativeValue: String) {
    LEGACY("legacy"),
    MORPH_QUIET("morph_quiet"),
    MORPH_BALANCED("morph_balanced"),
    MORPH_PARANOID("morph_paranoid");

    companion object {
        fun fromStored(value: String): VpnProtocol =
            entries.firstOrNull { it.nativeValue == value } ?: LEGACY
    }
}

data class VpnProfile(
    val id: String,
    val name: String,
    val endpoint: String,
    val serverPublicKey: String,
    val clientPrivateKey: String,
    val protocol: VpnProtocol = VpnProtocol.LEGACY,
    val accountId: String? = null,
    val serverId: String? = null,
    val validUntil: Long = 0,
) {
    fun validate(): VpnProfile {
        require(isValidEndpoint(endpoint)) { "Неверный IPv4:port" }
        require(id.isNotBlank()) { "У профиля нет идентификатора" }
        require(name.isNotBlank()) { "Введите имя профиля" }
        require(decodeKey(serverPublicKey).size == KEY_SIZE) { "Неверный ключ сервера" }
        require(decodeKey(clientPrivateKey).size == KEY_SIZE) { "Неверный ключ клиента" }
        return this
    }

    fun toJson(): String = JSONObject()
        .put("version", 1)
        .put("id", id)
        .put("name", name)
        .put("endpoint", endpoint)
        .put("serverPublicKey", serverPublicKey)
        .put("clientPrivateKey", clientPrivateKey)
        .put("protocol", protocol.nativeValue)
        .put("accountId", accountId)
        .put("serverId", serverId)
        .put("validUntil", validUntil)
        .toString()

    companion object {
        private const val KEY_SIZE = 32

        fun fromJson(json: String): VpnProfile {
            val value = JSONObject(json)
            require(value.getInt("version") == 1) { "Неподдерживаемая версия профиля" }
            return VpnProfile(
                id = value.optString("id").ifBlank { UUID.randomUUID().toString() },
                name = value.optString("name").ifBlank { value.getString("endpoint") },
                endpoint = value.getString("endpoint"),
                serverPublicKey = value.getString("serverPublicKey"),
                clientPrivateKey = value.getString("clientPrivateKey"),
                protocol = VpnProtocol.fromStored(value.optString("protocol", "legacy")),
                accountId = value.optString("accountId").takeIf { it.isNotBlank() && it != "null" },
                serverId = value.optString("serverId").takeIf { it.isNotBlank() && it != "null" },
                validUntil = value.optLong("validUntil", 0),
            ).validate()
        }

        private fun decodeKey(value: String): ByteArray =
            Base64.decode(value, Base64.URL_SAFE or Base64.NO_WRAP or Base64.NO_PADDING)

        private fun isValidEndpoint(value: String): Boolean {
            val separator = value.lastIndexOf(':')
            if (separator <= 0 || separator == value.lastIndex) return false
            val octets = value.substring(0, separator).split('.')
            val port = value.substring(separator + 1).toIntOrNull()
            return octets.size == 4 && octets.all { it.toIntOrNull() in 0..255 } && port in 1..65535
        }
    }
}
