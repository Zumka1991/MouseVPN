package dev.mousevpn.app

import android.app.Activity
import android.content.ClipData
import android.content.ClipboardManager
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.text.Editable
import android.text.InputType
import android.text.TextWatcher
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView
import org.json.JSONObject
import java.text.DateFormat
import java.util.Date
import java.util.UUID
import java.util.concurrent.Executors

class PaymentActivity : Activity() {
    private lateinit var manager: AccountManager
    private lateinit var status: TextView
    private lateinit var detailsCard: LinearLayout
    private lateinit var recipient: TextView
    private lateinit var cardNumber: TextView
    private lateinit var instructions: TextView
    private lateinit var form: LinearLayout
    private lateinit var months: EditText
    private lateinit var note: EditText
    private lateinit var total: TextView
    private lateinit var submit: Button
    private lateinit var pending: TextView
    private lateinit var history: LinearLayout
    private var details: JSONObject? = null
    private var draftId = UUID.randomUUID().toString()
    private var draftSignature = ""
    private var minimum = 1
    private var maximum = 120
    private var monthPrice = 300
    private var policyReady = false
    private lateinit var terms: TextView
    private var busy = false
    private var started = false
    private var approvedIds = emptySet<String>()
    private val executor = Executors.newSingleThreadExecutor()
    private val handler = Handler(Looper.getMainLooper())
    private val poll = object : Runnable {
        override fun run() {
            if (started && manager.signedIn()) load(false)
            if (started) handler.postDelayed(this, 8000)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        manager = AccountManager(this)
        val content = AppUi.screen(this, AppUi.Tab.PAYMENT).content
        AppUi.header(content, "Оплата", "Продлите подписку на телефон и компьютер.")
        status = AppUi.status(content)
        if (!manager.signedIn()) {
            AppUi.text(content, "Войдите в аккаунт, чтобы увидеть реквизиты и отправить заявку.", 16f)
            AppUi.button(content, "Войти в аккаунт", primary = true) {
                startActivity(android.content.Intent(this, AccountActivity::class.java)); finish()
            }
            return
        }
        detailsCard = AppUi.card(content).apply { visibility = View.GONE }
        AppUi.text(detailsCard, "1. Переведите в своём банке", 18f, bold = true)
        AppUi.space(detailsCard)
        recipient = AppUi.text(detailsCard, "", 15f, secondary = true)
        cardNumber = AppUi.text(detailsCard, "", 21f, bold = true).apply { setTextIsSelectable(true) }
        AppUi.button(detailsCard, "Скопировать номер карты") {
            val number = details?.optString("card_number") ?: return@button
            (getSystemService(CLIPBOARD_SERVICE) as ClipboardManager).setPrimaryClip(ClipData.newPlainText("Карта получателя", number))
            showStatus("Номер карты скопирован")
        }
        instructions = AppUi.text(detailsCard, "", 14f, secondary = true)
        form = AppUi.card(content).apply { visibility = View.GONE }
        AppUi.text(form, "2. Сообщите об оплате", 18f, bold = true)
        terms = AppUi.text(form, "Загружаем условия оплаты…", 14f, secondary = true)
        months = AppUi.input(form, "Количество месяцев", "Месяцы", InputType.TYPE_CLASS_NUMBER, 3)
        months.setText(savedInstanceState?.getString("months") ?: "")
        total = AppUi.text(form, "", 26f, bold = true).apply { setTextColor(getColor(R.color.accent)) }
        note = AppUi.input(form, "Комментарий (необязательно)", "Имя отправителя, дата и время перевода", InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_MULTI_LINE, 500, multiline = true)
        note.setText(savedInstanceState?.getString("note") ?: "")
        draftId = savedInstanceState?.getString("draftId") ?: draftId
        draftSignature = savedInstanceState?.getString("signature") ?: ""
        submit = AppUi.button(form, "Я оплатил — отправить заявку", primary = true) { send() }
        months.addTextChangedListener(object : TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) { amount() }
            override fun afterTextChanged(s: Editable?) {}
        })
        amount()
        pending = AppUi.text(content, "Заявка на проверке. Повторно переводить деньги не нужно. Результат появится здесь автоматически.", 15f).apply { visibility = View.GONE }
        history = AppUi.card(content)
        AppUi.button(content, "Обновить") { load(true) }
        load(true)
    }
    private fun amount() {
        val count = months.text.toString().toIntOrNull()
        total.text = if (!policyReady) "Загружаем условия…" else if (count != null && count in minimum..maximum) "${count * monthPrice} ₽" else "От $minimum до $maximum мес."
        submit.isEnabled = !busy && policyReady && details?.optBoolean("enabled") == true && count != null && count in minimum..maximum
    }
    private fun showStatus(text: String) { status.text = text; status.visibility = if (text.isBlank()) View.GONE else View.VISIBLE }
    private fun load(updateDetails: Boolean) = work {
        val view = manager.billing()
        val requests = view.getJSONArray("requests")
        val approved = (0 until requests.length()).map { requests.getJSONObject(it) }.filter { it.optString("status") == "approved" }.map { it.getString("id") }.toSet()
        if (approved.any { it !in approvedIds }) manager.refresh()
        runOnUiThread {
            if (isFinishing || isDestroyed) return@runOnUiThread
            approvedIds = approved
            paint(view, updateDetails || details == null)
        }
    }
    private fun send() {
        val count = months.text.toString().toIntOrNull() ?: return
        val d = details ?: return
        if (!policyReady || count !in minimum..maximum || !d.optBoolean("enabled")) return
        val text = note.text.toString().trim()
        val revision = d.getLong("revision")
        val signature = JSONObject().put("months", count).put("note", text).put("revision", revision).toString()
        if (draftSignature != signature) { draftId = UUID.randomUUID().toString(); draftSignature = signature }
        val id = draftId
        work {
            manager.requestPayment(id, count, text, revision)
            val view = manager.billing()
            runOnUiThread {
                if (isFinishing || isDestroyed) return@runOnUiThread
                draftSignature = ""; paint(view, false)
                showStatus("Заявка отправлена. Ожидайте проверки поступления.")
            }
        }
    }
    private fun paint(view: JSONObject, updateDetails: Boolean) {
        minimum = view.getInt("min_months"); maximum = view.getInt("max_months"); monthPrice = view.getInt("month_price")
        policyReady = minimum in 1..120 && maximum in minimum..120 && monthPrice > 0
        terms.text = "$monthPrice ₽ в месяц · от $minimum мес. Владелец проверит поступление и добавит месяцы."
        if (months.text.isBlank()) months.setText(minimum.toString())
        showStatus("")
        if (updateDetails) details = view.optJSONObject("details")
        val d = details
        val enabled = d?.optBoolean("enabled") == true
        detailsCard.visibility = if (enabled) View.VISIBLE else View.GONE
        recipient.text = listOf(d?.optString("bank") ?: "", d?.optString("recipient") ?: "").joinToString(" · ")
        cardNumber.text = d?.optString("card_number")?.chunked(4)?.joinToString(" ") ?: ""
        instructions.text = d?.optString("instructions") ?: ""
        if (!enabled) showStatus("Реквизиты пока не опубликованы. Напишите в поддержку.")
        val requests = view.getJSONArray("requests")
        var waiting = false
        history.removeAllViews()
        AppUi.text(history, "Мои заявки", 18f, bold = true)
        if (requests.length() == 0) AppUi.text(history, "Заявок пока нет.", 14f, secondary = true)
        for (i in 0 until requests.length()) {
            val r = requests.getJSONObject(i)
            val label = when(r.getString("status")) { "pending" -> { waiting = true; "На проверке" }; "approved" -> "Подтверждено"; else -> "Отклонено" }
            AppUi.space(history, 18)
            AppUi.text(history, "${r.getInt("amount_rub")} ₽ · ${r.getInt("months")} мес. · $label", 15f, bold = true)
            AppUi.text(history, DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT).format(Date(r.getLong("created_at") * 1000)), 12f, secondary = true)
            if (r.optString("admin_note").isNotBlank()) AppUi.text(history, r.getString("admin_note"), 14f)
            if (!r.isNull("valid_until")) AppUi.text(history, "Продлена до " + DateFormat.getDateInstance().format(Date(r.getLong("valid_until") * 1000)), 14f)
        }
        pending.visibility = if (waiting) View.VISIBLE else View.GONE
        form.visibility = if (enabled && !waiting) View.VISIBLE else View.GONE
    }
    private fun work(job: () -> Unit) {
        if (busy || !manager.signedIn()) return
        busy = true; if (::submit.isInitialized) amount()
        executor.execute {
            val result = runCatching(job)
            runOnUiThread {
                if (isFinishing || isDestroyed) return@runOnUiThread
                busy = false; if (::submit.isInitialized) amount()
                result.onFailure { showStatus(it.message ?: "Не удалось связаться с сервисом. Попробуйте обновить.") }
            }
        }
    }
    override fun onStart() { super.onStart(); started = true; handler.postDelayed(poll, 8000) }
    override fun onStop() { started = false; handler.removeCallbacks(poll); super.onStop() }
    override fun onSaveInstanceState(outState: Bundle) {
        if (::months.isInitialized) { outState.putString("months", months.text.toString()); outState.putString("note", note.text.toString()); outState.putString("draftId", draftId); outState.putString("signature", draftSignature) }
        super.onSaveInstanceState(outState)
    }
    override fun onDestroy() { executor.shutdownNow(); super.onDestroy() }
}
