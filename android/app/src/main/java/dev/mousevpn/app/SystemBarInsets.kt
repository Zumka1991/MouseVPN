package dev.mousevpn.app

import android.os.Build
import android.view.View
import android.view.WindowInsets

/** Adds stable content spacing outside status and navigation bars. */
@Suppress("DEPRECATION")
internal fun View.applySystemBarPadding(
    startDp: Int,
    topDp: Int,
    endDp: Int,
    bottomDp: Int,
    includeKeyboard: Boolean = false,
) {
    val density = resources.displayMetrics.density
    fun Int.dp() = (this * density).toInt()

    setOnApplyWindowInsetsListener { view, windowInsets ->
        val left: Int
        val top: Int
        val right: Int
        val bottom: Int
        if (Build.VERSION.SDK_INT >= 30) {
            val types = WindowInsets.Type.systemBars() or if (includeKeyboard) WindowInsets.Type.ime() else 0
            val bars = windowInsets.getInsets(types)
            left = bars.left
            top = bars.top
            right = bars.right
            bottom = bars.bottom
        } else {
            left = windowInsets.systemWindowInsetLeft
            top = windowInsets.systemWindowInsetTop
            right = windowInsets.systemWindowInsetRight
            bottom = windowInsets.systemWindowInsetBottom
        }
        view.setPadding(
            startDp.dp() + left,
            topDp.dp() + top,
            endDp.dp() + right,
            bottomDp.dp() + bottom,
        )
        windowInsets
    }
    requestApplyInsets()
}
