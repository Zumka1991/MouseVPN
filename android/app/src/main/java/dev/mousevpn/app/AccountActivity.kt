package dev.mousevpn.app

import android.app.Activity
import android.app.AlertDialog
import android.os.Bundle
import android.text.InputType
import android.view.View
import android.widget.LinearLayout
import android.widget.TextView
import org.json.JSONObject
import java.text.DateFormat
import java.util.Date
import java.util.concurrent.Executors

class AccountActivity : Activity() {
    private lateinit var manager: AccountManager
    private lateinit var content: LinearLayout
    private lateinit var status: TextView
    private val executor = Executors.newSingleThreadExecutor()
    private var busy = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        manager = AccountManager(this)
        content = AppUi.screen(this, AppUi.Tab.ACCOUNT).content
        render(manager.state()?.optJSONObject("account"))
        if (manager.signedIn()) work { manager.refresh() }
    }

    private fun render(account: JSONObject?) {
        content.removeAllViews()
        AppUi.header(content, "Аккаунт", "Подписка, доступные серверы и ваши устройства.")
        if (!manager.signedIn()) {
            val form = AppUi.card(content)
            AppUi.text(form, "Вход в MouseVPN", 20f, bold = true)
            AppUi.space(form, 6)
            AppUi.text(form, "Используйте почту и пароль вашего аккаунта.", 14f, secondary = true)
            status = AppUi.status(form)
            val configured = BuildConfig.ACCOUNT_SERVICE_URL
            val savedBase = manager.state()?.optString("base")?.ifBlank { configured } ?: configured
            val base = if (configured.isBlank()) AppUi.input(form, "Адрес сервиса", "https://vpn.example.ru",
                InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_URI, 512).apply { setText(savedBase) } else null
            val login = AppUi.input(form, "Почта", "you@example.ru",
                InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_EMAIL_ADDRESS, 254)
            login.setText(manager.state()?.optString("login") ?: "")
            val password = AppUi.input(form, "Пароль", "Ваш пароль",
                InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD, 256)
            button(form, "Войти в аккаунт", primary = true) {
                val address = base?.text?.toString() ?: savedBase
                val username = login.text.toString().trim()
                val secret = password.text.toString()
                if (username.isBlank() || secret.isBlank()) {
                    showStatus("Введите почту и пароль.", error = true)
                } else {
                    password.text.clear()
                    work { manager.signIn(address, username, secret) }
                }
            }
            button(form, "Создать аккаунт") {
                AppUi.openLink(this, if (BuildConfig.ACCOUNT_FALLBACK_URL.isNotBlank())
                    "https://myaifriend.su/mousevpn/#request" else "https://mousevpn.space/#request")
            }
            val plan = AppUi.card(content)
            AppUi.text(plan, "Одна подписка · два устройства", 17f, bold = true)
            AppUi.space(plan, 8)
            AppUi.text(plan, "300 ₽ в месяц", 23f, bold = true).setTextColor(getColor(R.color.accent))
            AppUi.space(plan, 6)
            AppUi.text(plan, "300 ₽ в месяц. Оплату подтверждает владелец — автоматических списаний нет.", 14f, secondary = true)
            return
        }

        val summary = AppUi.card(content)
        AppUi.text(summary, account?.optString("login") ?: "", 17f, bold = true)
        AppUi.space(summary, 12)
        val active = account?.optBoolean("active") == true
        AppUi.text(summary, if (active) "Подписка активна" else "Ожидает активации", 21f, bold = true)
            .setTextColor(getColor(if (active) R.color.accent else R.color.text_primary))
        val until = account?.optLong("valid_until") ?: 0
        val untilText = if (until > 0) DateFormat.getDateInstance(DateFormat.MEDIUM).format(Date(until * 1000)) else ""
        AppUi.space(summary, 6)
        AppUi.text(summary, if (active) "Доступ до " + untilText else if (until > 0)
            "Подписка закончилась " + untilText else "Доступ появится после подтверждения оплаты.", 14f, secondary = true)
        status = AppUi.status(summary)
        button(summary, "Оплата и продление", primary = true) { startActivity(android.content.Intent(this, PaymentActivity::class.java)); finish() }
        button(summary, "Обновить данные") { work { manager.refresh() } }
        if (!active) button(summary, "Связаться с владельцем", primary = true) {
            AppUi.openLink(this, "https://t.me/napsy13")
        }

        val serversCard = AppUi.card(content)
        AppUi.text(serversCard, "Ваши серверы", 18f, bold = true)
        AppUi.space(serversCard, 5)
        AppUi.text(serversCard, "Выберите сервер для следующего подключения. Режим выбирается отдельно на главном экране.", 13f, secondary = true)
        val servers = account?.optJSONArray("servers")
        if (servers == null || servers.length() == 0) {
            AppUi.space(serversCard, 12)
            AppUi.text(serversCard, "После активации здесь появятся разрешённые вам серверы.", 14f, secondary = true)
        }
        if (servers != null) for (index in 0 until servers.length()) {
            val server = servers.getJSONObject(index)
            val selected = ProfileStore(this).selected()?.id == server.getString("id")
            button(serversCard, (if (selected) "✓  " else "") + server.getString("name") + " · " + manager.serverLoad(server)) {
                runCatching { ProfileStore(this).select(server.getString("id")); finish() }
                    .onFailure { showStatus("Устройство отключено. Выйдите и войдите снова, чтобы зарегистрировать его.", true) }
            }
        }

        val devicesCard = AppUi.card(content)
        val devices = account?.optJSONArray("devices")
        AppUi.text(devicesCard, "Устройства · " + (devices?.length() ?: 0) + " из 2", 18f, bold = true)
        AppUi.space(devicesCard, 5)
        AppUi.text(devicesCard, "Телефон и компьютер используют одну подписку.", 13f, secondary = true)
        if (devices != null) for (index in 0 until devices.length()) {
            val device = devices.getJSONObject(index)
            val current = device.getString("public_key") == manager.state()?.optString("public_key")
            AppUi.space(devicesCard, 16)
            AppUi.text(devicesCard, device.getString("name"), 16f, bold = true)
            AppUi.text(devicesCard, if (current) "Это устройство" else device.getString("platform"), 13f, secondary = true)
            button(devicesCard, "Отключить устройство", danger = true) {
                AlertDialog.Builder(this).setTitle("Отключить устройство?")
                    .setMessage(device.getString("name") + " потеряет доступ. Освободится место для другого устройства.")
                    .setNegativeButton("Отмена", null)
                    .setPositiveButton("Отключить") { _, _ -> work { manager.revoke(device.getString("id")) } }.show()
            }
        }
        button(content, "Выйти из аккаунта", danger = true) { work { manager.logout(); null } }
    }

    private fun button(parent: LinearLayout, value: String, primary: Boolean = false,
        danger: Boolean = false, action: () -> Unit) =
        AppUi.button(parent, value, primary, danger) { if (!busy) action() }

    private fun showStatus(message: String, error: Boolean = false) {
        status.text = message
        status.visibility = View.VISIBLE
        status.setTextColor(getColor(if (error) R.color.error else R.color.text_secondary))
    }

    private fun work(job: () -> JSONObject?) {
        if (busy) return
        busy = true
        showStatus("Обновляем данные…")
        executor.execute {
            val result = runCatching(job)
            runOnUiThread {
                if (isFinishing || isDestroyed) return@runOnUiThread
                busy = false
                result.onSuccess { render(it) }
                    .onFailure { showStatus(it.message ?: "Сервис временно недоступен", true) }
            }
        }
    }

    override fun onDestroy() { executor.shutdownNow(); super.onDestroy() }
}
