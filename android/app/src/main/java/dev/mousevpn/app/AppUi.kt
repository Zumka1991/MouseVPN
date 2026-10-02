package dev.mousevpn.app

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.content.res.ColorStateList
import android.graphics.Typeface
import android.net.Uri
import android.text.InputFilter
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.view.WindowManager
import android.widget.Button
import android.widget.EditText
import android.widget.ImageView
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView

internal fun Context.dp(value: Int): Int = (value * resources.displayMetrics.density).toInt()

internal object AppUi {
    enum class Tab { CONNECTION, ACCOUNT, PAYMENT, SUPPORT }
    data class Screen(val content: LinearLayout, val scroll: ScrollView)

    fun screen(activity: Activity, selected: Tab): Screen {
        activity.window.setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_ADJUST_RESIZE)
        val root = LinearLayout(activity).apply {
            orientation = LinearLayout.VERTICAL
            setBackgroundColor(activity.getColor(R.color.background))
            applySystemBarPadding(0, 0, 0, 0, includeKeyboard = true)
        }
        val content = LinearLayout(activity).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(activity.dp(20), activity.dp(24), activity.dp(20), activity.dp(24))
        }
        val scroll = ScrollView(activity).apply {
            isFillViewport = true
            overScrollMode = View.OVER_SCROLL_NEVER
            addView(content)
        }
        root.addView(scroll, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f))
        val nav = LinearLayout(activity)
        root.addView(nav)
        navigation(activity, nav, selected)
        activity.setContentView(root)
        return Screen(content, scroll)
    }

    fun navigation(activity: Activity, container: LinearLayout, selected: Tab) {
        container.orientation = LinearLayout.VERTICAL
        container.setBackgroundColor(activity.getColor(R.color.background))
        container.addView(View(activity).apply { setBackgroundColor(activity.getColor(R.color.divider)) },
            LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, activity.dp(1)))
        val row = LinearLayout(activity).apply { setPadding(activity.dp(10), activity.dp(8), activity.dp(10), activity.dp(8)) }
        container.addView(row)
        val tabs = listOf(
            Triple(Tab.CONNECTION, "Подключение", R.drawable.ic_nav_connection),
            Triple(Tab.ACCOUNT, "Аккаунт", R.drawable.ic_nav_account),
            Triple(Tab.PAYMENT, "Оплата", R.drawable.ic_nav_payment),
            Triple(Tab.SUPPORT, "Помощь", R.drawable.ic_nav_support),
        )
        tabs.forEach { (tab, label, icon) ->
            val color = activity.getColor(if (tab == selected) R.color.accent else R.color.text_secondary)
            val item = LinearLayout(activity).apply {
                orientation = LinearLayout.VERTICAL
                gravity = Gravity.CENTER
                isClickable = true
                isFocusable = true
                isSelected = tab == selected
                contentDescription = label
                if (tab == selected) setBackgroundResource(R.drawable.bg_nav_selected)
            }
            val image = ImageView(activity).apply { setImageResource(icon); imageTintList = ColorStateList.valueOf(color) }
            item.addView(image, LinearLayout.LayoutParams(activity.dp(23), activity.dp(23)))
            val title = TextView(activity).apply {
                text = label; textSize = 11f; setTextColor(color); gravity = Gravity.CENTER
                if (tab == Tab.SUPPORT) id = R.id.navSupportLabel
            }
            item.addView(title, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply { topMargin = activity.dp(5) })
            item.setOnClickListener {
                if (tab == selected) return@setOnClickListener
                val destination = when (tab) {
                    Tab.CONNECTION -> MainActivity::class.java
                    Tab.ACCOUNT -> AccountActivity::class.java
                    Tab.PAYMENT -> PaymentActivity::class.java
                    Tab.SUPPORT -> SupportActivity::class.java
                }
                activity.startActivity(Intent(activity, destination).addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP))
                if (selected != Tab.CONNECTION) activity.finish()
            }
            row.addView(item, LinearLayout.LayoutParams(0, activity.dp(62), 1f).apply {
                marginStart = activity.dp(3); marginEnd = activity.dp(3)
            })
        }
    }

    fun header(parent: LinearLayout, title: String, subtitle: String) {
        text(parent, title, 27f, bold = true)
        text(parent, subtitle, 14f, secondary = true).apply {
            setPadding(0, parent.context.dp(6), 0, parent.context.dp(22))
        }
    }

    fun card(parent: LinearLayout): LinearLayout = LinearLayout(parent.context).apply {
        orientation = LinearLayout.VERTICAL
        setBackgroundResource(R.drawable.bg_card)
        setPadding(context.dp(18), context.dp(18), context.dp(18), context.dp(18))
        parent.addView(this, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply { bottomMargin = context.dp(16) })
    }

    fun text(parent: LinearLayout, value: String, size: Float = 15f, secondary: Boolean = false, bold: Boolean = false): TextView = TextView(parent.context).apply {
        text = value; textSize = size
        setTextColor(context.getColor(if (secondary) R.color.text_secondary else R.color.text_primary))
        if (bold) setTypeface(typeface, Typeface.BOLD)
        setLineSpacing(context.dp(3).toFloat(), 1f)
        parent.addView(this, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT))
    }

    fun space(parent: LinearLayout, height: Int = 12) {
        parent.addView(View(parent.context), LinearLayout.LayoutParams(1, parent.context.dp(height)))
    }

    fun status(parent: LinearLayout): TextView = text(parent, "", 13f, secondary = true).apply {
        accessibilityLiveRegion = View.ACCESSIBILITY_LIVE_REGION_POLITE
        visibility = View.GONE
        setPadding(0, context.dp(10), 0, context.dp(10))
    }

    fun input(parent: LinearLayout, label: String, hintText: String, type: Int, maximum: Int, multiline: Boolean = false): EditText {
        space(parent, 14)
        text(parent, label, 13f, secondary = true)
        val field = EditText(parent.context).apply {
            hint = hintText; inputType = type; textSize = 15f
            filters = arrayOf(InputFilter.LengthFilter(maximum))
            setSingleLine(!multiline)
            if (multiline) { minLines = 4; gravity = Gravity.TOP or Gravity.START }
            setBackgroundResource(R.drawable.bg_input)
            backgroundTintList = null
            setTextColor(context.getColor(R.color.text_primary))
            setHintTextColor(context.getColor(R.color.text_secondary))
            setPadding(context.dp(14), context.dp(14), context.dp(14), context.dp(14))
        }
        parent.addView(field, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, if (multiline) ViewGroup.LayoutParams.WRAP_CONTENT else parent.context.dp(54)).apply { topMargin = parent.context.dp(6) })
        return field
    }

    fun button(parent: LinearLayout, value: String, primary: Boolean = false, danger: Boolean = false, action: () -> Unit): Button = Button(parent.context).apply {
        text = value; textSize = 14f; isAllCaps = false
        setTypeface(typeface, Typeface.BOLD)
        setBackgroundResource(if (primary) R.drawable.bg_primary_button else R.drawable.bg_secondary_button)
        backgroundTintList = null
        setTextColor(context.getColor(when { danger -> R.color.error; primary -> R.color.on_accent; else -> R.color.text_primary }))
        minHeight = context.dp(50); minimumHeight = context.dp(50)
        setPadding(context.dp(14), context.dp(10), context.dp(14), context.dp(10))
        setOnClickListener { action() }
        parent.addView(this, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT).apply { topMargin = context.dp(12) })
    }

    fun openLink(activity: Activity, url: String) {
        activity.startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url)))
    }
}
