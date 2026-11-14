package win.cheems.core;
import android.app.Activity;
import android.os.Bundle;
import android.graphics.Color;
import android.widget.*;
public class MainActivity extends Activity {
 private ProxyCore core;
 private TextView status,metrics,logs;
 private final StringBuilder history=new StringBuilder();
 private final int purple=Color.rgb(164,116,255);
 @Override public void onCreate(Bundle state){
  super.onCreate(state);
  LinearLayout layout=new LinearLayout(this);layout.setOrientation(LinearLayout.VERTICAL);
  layout.setPadding(32,48,32,24);layout.setBackgroundColor(Color.rgb(18,16,27));
  layout.addView(text("CHEEMS CORE",26,purple));
  layout.addView(text("V0.1 · Independent experimental engine",13,Color.LTGRAY));
  status=text("● Stopped",20,Color.LTGRAY);layout.addView(status);
  metrics=text("Connections: 0\nUpload: 0 B · Download: 0 B",16,Color.WHITE);layout.addView(metrics);
  logs=text("Ready. Local proxy: 127.0.0.1:8899",13,Color.LTGRAY);
  core=new ProxyCore(s->runOnUiThread(()->{history.append(s).append('\n');if(history.length()>3500)history.delete(0,1000);logs.setText(history.toString());refresh();}));
  Button start=new Button(this);start.setText("Start local proxy");layout.addView(start);
  Button stop=new Button(this);stop.setText("Stop local proxy");layout.addView(stop);
  start.setOnClickListener(v->{try{core.start();refresh();}catch(Exception e){logs.setText("Start failed: "+e.getMessage());}});
  stop.setOnClickListener(v->{core.stop();refresh();});
  layout.addView(text("Loopback only. No VPNService or system-wide routing.",13,Color.LTGRAY));
  ScrollView scroll=new ScrollView(this);scroll.addView(logs);layout.addView(scroll);
  setContentView(layout);
 }
 private TextView text(String s,int sp,int color){TextView t=new TextView(this);t.setText(s);t.setTextSize(sp);t.setTextColor(color);t.setPadding(0,14,0,14);return t;}
 private void refresh(){status.setText(core.running()?"● Running":"● Stopped");status.setTextColor(core.running()?purple:Color.LTGRAY);metrics.setText("Connections: "+core.active()+"\nUpload: "+core.uploaded()+" B · Download: "+core.downloaded()+" B");}
 @Override protected void onDestroy(){core.stop();super.onDestroy();}
}