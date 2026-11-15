package win.cheems.core;

import android.app.Activity;
import android.app.AlertDialog;
import android.widget.Button;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.Robolectric;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.android.controller.ActivityController;
import org.robolectric.annotation.Config;
import static org.junit.Assert.*;

@RunWith(RobolectricTestRunner.class)
@Config(sdk = {28, 35}, manifest = Config.NONE)
public class TlsChoiceDialogTest {
  @Test public void explanationDoesNotHideConnectionActions() {
    try (ActivityController<Activity> controller = Robolectric.buildActivity(Activity.class).setup()) {
      Activity activity = controller.get();
      for (int selected = 0; selected < 3; selected++) {
        AtomicInteger chosen = new AtomicInteger(-1);
        AlertDialog dialog = TlsChoiceDialog.show(activity,
            () -> chosen.set(0), () -> chosen.set(1), () -> chosen.set(2));
        String[] tags = {"tls-strict", "tls-ca", "tls-unverified"};
        for (String tag : tags) {
          Button button = dialog.getWindow().getDecorView().findViewWithTag(tag);
          assertNotNull(tag, button);
          assertTrue(tag, button.isShown());
          assertTrue(tag, button.isEnabled());
        }
        assertTrue(dialog.getButton(AlertDialog.BUTTON_NEGATIVE).isShown());
        Button button = dialog.getWindow().getDecorView().findViewWithTag(tags[selected]);
        button.performClick();
        assertEquals(selected, chosen.get());
        assertFalse(dialog.isShowing());
      }
    }
  }
}
