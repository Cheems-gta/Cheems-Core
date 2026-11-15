package win.cheems.core;

import android.app.AlertDialog;
import android.content.Context;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

/** Keep the explanation and actions in one scrollable view: AlertDialog's
 * message and list slots are mutually exclusive on the platform. */
final class TlsChoiceDialog {
  static AlertDialog show(Context context, Runnable strict, Runnable customCA, Runnable unverified) {
    int padding = Math.round(20 * context.getResources().getDisplayMetrics().density);
    LinearLayout content = new LinearLayout(context);
    content.setOrientation(LinearLayout.VERTICAL);
    content.setPadding(padding, padding / 2, padding, padding / 2);
    TextView explanation = new TextView(context);
    explanation.setText("订阅要求跳过证书验证，但这可能允许他人冒充节点。优先使用可信 CA 或证书指纹。以下选择仅对本次连接有效。");
    explanation.setTextSize(16);
    content.addView(explanation, new LinearLayout.LayoutParams(-1, -2));
    ScrollView scroll = new ScrollView(context);
    scroll.addView(content, new ScrollView.LayoutParams(-1, -2));
    AlertDialog dialog = new AlertDialog.Builder(context)
        .setTitle("节点 TLS 证书验证方式")
        .setView(scroll)
        .setNegativeButton("取消", null)
        .create();
    addAction(context, content, dialog, "tls-strict", "严格验证并尝试（推荐）", strict);
    addAction(context, content, dialog, "tls-ca", "粘贴可信 CA 证书（PEM，本次）", customCA);
    addAction(context, content, dialog, "tls-unverified", "按订阅跳过验证（高风险，本次）", unverified);
    dialog.show();
    return dialog;
  }

  private static void addAction(Context context, LinearLayout parent, AlertDialog dialog,
      String tag, String text, Runnable action) {
    Button button = new Button(context);
    button.setTag(tag);
    button.setText(text);
    button.setAllCaps(false);
    parent.addView(button, new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT,
        ViewGroup.LayoutParams.WRAP_CONTENT));
    button.setOnClickListener(view -> { dialog.dismiss(); action.run(); });
  }

  private TlsChoiceDialog() {}
}
