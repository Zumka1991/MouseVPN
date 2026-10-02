package dev.mousevpn.app

import android.app.Activity
import android.content.Intent
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.text.InputType
import android.view.View
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView
import org.json.JSONArray
import org.json.JSONObject
import java.text.DateFormat
import java.util.Date
import java.util.concurrent.Executors

class SupportActivity : Activity() {
    private lateinit var manager: AccountManager
    private lateinit var screen: AppUi.Screen
    private lateinit var content: LinearLayout
    private lateinit var status: TextView
    private val executor = Executors.newSingleThreadExecutor()
    private val handler = Handler(Looper.getMainLooper())
    private var busy = false
    private var current: JSONObject? = null
    private var subjectField: EditText? = null
    private var bodyField: EditText? = null
    private var replyField: EditText? = null
    private var ticketList: LinearLayout? = null
    private var messageList: LinearLayout? = null
    private var subjectDraft = ""
    private var bodyDraft = ""
    private val replyDrafts = mutableMapOf<String, String>()
    private val poll = object : Runnable {
        override fun run() {
            if (!busy) reload(automatic = true)
            handler.postDelayed(this, if (current == null) 5_000 else 3_000)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        manager = AccountManager(this)
        screen = AppUi.screen(this, AppUi.Tab.SUPPORT)
        content = screen.content
        header("Помощь", "Личные сообщения и ответы администрации.")
        if (!manager.signedIn()) {
            val card = AppUi.card(content)
            AppUi.text(card, "Мы на связи", 21f, bold = true)
            AppUi.space(card, 8)
            AppUi.text(card, "Войдите в аккаунт, чтобы написать вопрос и получить ответ прямо здесь.", 15f, secondary = true)
            button(card, "Войти в аккаунт", primary = true) {
                startActivity(Intent(this, AccountActivity::class.java)); finish()
            }
        } else reload()
    }

    override fun onStart() { super.onStart(); handler.postDelayed(poll, 3_000) }
    override fun onStop() { handler.removeCallbacks(poll); super.onStop() }
    override fun onDestroy() { executor.shutdownNow(); super.onDestroy() }

    private fun rememberDrafts() {
        subjectField?.let { subjectDraft = it.text.toString() }
        bodyField?.let { bodyDraft = it.text.toString() }
        val id = current?.getJSONObject("ticket")?.getString("id")
        if (id != null) replyField?.let { replyDrafts[id] = it.text.toString() }
    }

    private fun reload(automatic: Boolean = false) {
        if (!manager.signedIn()) return
        val id = current?.getJSONObject("ticket")?.getString("id")
        val position = screen.scroll.scrollY
        if (id == null) work(quiet = automatic) {
            val tickets = manager.tickets()
            return@work {
                if (current == null) {
                    if (automatic && ticketList != null) renderTicketRows(ticketList!!, tickets)
                    else renderList(tickets)
                    screen.scroll.post { screen.scroll.scrollTo(0, position) }
                }
            }
        } else work(quiet = automatic) {
            val detail = manager.ticket(id)
            return@work {
                if (current?.getJSONObject("ticket")?.getString("id") == id) {
                    if (automatic && messageList != null) updateConversation(detail)
                    else {
                        renderTicket(detail)
                        screen.scroll.post { screen.scroll.scrollTo(0, position) }
                    }
                }
            }
        }
    }

    private fun renderList(tickets: JSONArray) {
        rememberDrafts()
        current = null
        header("Помощь", "Личные сообщения и ответы администрации.")
        val list = AppUi.card(content)
        AppUi.text(list, "Переписка", 18f, bold = true)
        val rows = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        list.addView(rows)
        ticketList = rows
        renderTicketRows(rows, tickets)
        button(list, "Обновить переписку") { reload() }

        val form = AppUi.card(content)
        AppUi.text(form, "Написать в поддержку", 18f, bold = true)
        AppUi.space(form, 5)
        AppUi.text(form, "Расскажите, что случилось. Ответ появится в этом разделе.", 13f, secondary = true)
        val subject = AppUi.input(form, "Тема", "Например, не получается подключиться", InputType.TYPE_CLASS_TEXT, 80)
        val message = AppUi.input(form, "Ваш вопрос", "Опишите вопрос",
            InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_MULTI_LINE, 2000, multiline = true)
        subject.setText(subjectDraft); message.setText(bodyDraft)
        subjectField = subject; bodyField = message
        button(form, "Отправить вопрос", primary = true) {
            val title = subject.text.toString().trim()
            val body = message.text.toString().trim()
            if (title.isBlank() || body.isBlank()) showStatus("Укажите тему и напишите вопрос.", true)
            else work {
                val detail = manager.createTicket(title, body)
                return@work {
                    subject.text.clear(); message.text.clear()
                    subjectDraft = ""; bodyDraft = ""
                    renderTicket(detail); screen.scroll.scrollTo(0, 0)
                }
            }
        }
    }

    private fun renderTicketRows(list: LinearLayout, tickets: JSONArray) {
        list.removeAllViews()
        if (tickets.length() == 0) {
            AppUi.space(list, 10)
            AppUi.text(list, "Здесь будут ваши обращения и сообщения от владельца сервиса.", 14f, secondary = true)
        }
        for (index in 0 until tickets.length()) {
            val ticket = tickets.getJSONObject(index)
            button(list, (if (ticket.getLong("unread_count") > 0) "●  " else "") + ticket.getString("subject")) {
                work {
                    val detail = manager.ticket(ticket.getString("id"))
                    return@work { renderTicket(detail); screen.scroll.scrollTo(0, 0) }
                }
            }
            AppUi.text(list, if (ticket.optString("kind") == "announcement") "Сообщение администрации"
                else if (ticket.getString("status") == "closed") "Обращение закрыто" else "Обращение в поддержке",
                12f, secondary = true)
        }
    }

    private fun renderTicket(detail: JSONObject) {
        rememberDrafts()
        current = detail
        header("Переписка", detail.getJSONObject("ticket").getString("subject"))
        button(content, "← Все обращения и сообщения") {
            rememberDrafts(); current = null; replyField = null; reload()
        }
        AppUi.space(content, 16)
        val messages = detail.getJSONArray("messages")
        if (detail.getBoolean("has_more") && messages.length() > 0) {
            button(content, "Более ранние сообщения") {
                val id = detail.getJSONObject("ticket").getString("id")
                work {
                    val earlier = manager.ticket(id, messages.getJSONObject(0).getLong("id"))
                    val combined = earlier.getJSONArray("messages")
                    for (index in 0 until messages.length()) combined.put(messages.getJSONObject(index))
                    return@work { renderTicket(earlier.put("messages", combined)) }
                }
            }
        }
        val bubbles = LinearLayout(this).apply { orientation = LinearLayout.VERTICAL }
        content.addView(bubbles)
        messageList = bubbles
        renderMessages(bubbles, messages)
        val form = AppUi.card(content)
        val reply = AppUi.input(form, "Ответ", "Написать сообщение",
            InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_MULTI_LINE, 2000, multiline = true)
        val id = detail.getJSONObject("ticket").getString("id")
        reply.setText(replyDrafts[id] ?: "")
        replyField = reply
        button(form, "Отправить сообщение", primary = true) {
            val body = reply.text.toString().trim()
            if (body.isBlank()) showStatus("Напишите сообщение.", true)
            else work {
                val updated = manager.reply(id, body)
                return@work { reply.text.clear(); replyDrafts.remove(id); renderTicket(updated) }
            }
        }
    }

    private fun renderMessages(parent: LinearLayout, messages: JSONArray) {
        parent.removeAllViews()
        for (index in 0 until messages.length()) {
            val item = messages.getJSONObject(index)
            val admin = item.getString("author") == "admin"
            val bubble = AppUi.card(parent)
            val date = DateFormat.getDateTimeInstance(DateFormat.SHORT, DateFormat.SHORT)
                .format(Date(item.getLong("created_at") * 1000))
            AppUi.text(bubble, (if (admin) "Администрация" else "Вы") + " · " + date, 12f, secondary = true)
                .setTextColor(getColor(if (admin) R.color.accent else R.color.text_secondary))
            AppUi.space(bubble, 8)
            AppUi.text(bubble, item.getString("text"), 15f)
        }
    }

    private fun updateConversation(detail: JSONObject) {
        val old = current ?: return
        val previous = old.getJSONArray("messages")
        val recent = detail.getJSONArray("messages")
        val merged = sortedMapOf<Long, JSONObject>()
        for (index in 0 until previous.length()) previous.getJSONObject(index).let { merged[it.getLong("id")] = it }
        for (index in 0 until recent.length()) recent.getJSONObject(index).let { merged[it.getLong("id")] = it }
        val hasOlder = previous.length() > 0 && recent.length() > 0 &&
            previous.getJSONObject(0).getLong("id") < recent.getJSONObject(0).getLong("id")
        if (hasOlder) detail.put("has_more", old.getBoolean("has_more"))
        detail.put("messages", JSONArray(merged.values.toList()))
        current = detail
        if (merged.size == previous.length() && (previous.length() == 0 ||
            previous.getJSONObject(previous.length() - 1).getLong("id") == merged.lastKey())) return
        val parent = messageList ?: return
        val position = screen.scroll.scrollY
        val height = parent.height
        val bottom = content.height - screen.scroll.height - position < dp(96)
        val editing = replyField?.hasFocus() == true
        renderMessages(parent, detail.getJSONArray("messages"))
        screen.scroll.post {
            screen.scroll.scrollTo(0, when {
                editing -> position + parent.height - height
                bottom -> content.height
                else -> position
            })
        }
    }

    private fun header(title: String, subtitle: String) {
        content.removeAllViews()
        subjectField = null; bodyField = null; replyField = null
        ticketList = null; messageList = null
        AppUi.header(content, title, subtitle)
        status = AppUi.status(content)
    }

    private fun button(parent: LinearLayout, value: String, primary: Boolean = false, action: () -> Unit) =
        AppUi.button(parent, value, primary) { if (!busy) action() }

    private fun showStatus(message: String, error: Boolean = false) {
        status.text = message; status.visibility = View.VISIBLE
        status.setTextColor(getColor(if (error) R.color.error else R.color.text_secondary))
    }

    private fun work(quiet: Boolean = false, job: () -> (() -> Unit)) {
        if (busy) return
        busy = true
        if (!quiet) showStatus("Обновляем переписку…")
        executor.execute {
            val result = runCatching(job)
            runOnUiThread {
                if (isFinishing || isDestroyed) return@runOnUiThread
                busy = false
                result.onSuccess { it() }.onFailure { showStatus(it.message ?: "Сервис недоступен", true) }
            }
        }
    }
}
