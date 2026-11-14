package win.cheems.core;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.*;
import java.util.concurrent.atomic.*;
public final class ProxyCore {
 public interface Listener {void onUpdate(String event);}
 private final AtomicInteger active=new AtomicInteger();
 private final AtomicLong uploaded=new AtomicLong(),downloaded=new AtomicLong();
 private final ExecutorService workers=Executors.newCachedThreadPool();
 private volatile boolean running;
 private ServerSocket server;
 private final Listener listener;
 public ProxyCore(Listener listener){this.listener=listener;}
 public int active(){return active.get();}
 public long uploaded(){return uploaded.get();}
 public long downloaded(){return downloaded.get();}
 public boolean running(){return running;}
 private void log(String s){listener.onUpdate(s);}
 public synchronized void start() throws IOException{
  if(running)return;
  server=new ServerSocket();
  server.bind(new InetSocketAddress(InetAddress.getByName("127.0.0.1"),8899));
  running=true;
  workers.execute(()->{
   log("Listening on 127.0.0.1:8899");
   while(running){try{Socket c=server.accept();workers.execute(()->handle(c));}catch(IOException e){if(running)log("Accept error: "+e.getMessage());}}
  });
 }
 public synchronized void stop(){
  running=false;
  try{if(server!=null)server.close();}catch(IOException ignored){}
  log("Stopped (existing tunnels may finish)");
 }
 private void handle(Socket client){
  active.incrementAndGet();
  try(Socket c=client){
   c.setSoTimeout(10000);
   InputStream in=c.getInputStream();OutputStream out=c.getOutputStream();
   ByteArrayOutputStream header=new ByteArrayOutputStream();
   int b;
   while((b=in.read())!=-1&&header.size()<8192){
    header.write(b);
    if(header.size()>=4&&b=='\n'){
     byte[] h=header.toByteArray();int z=h.length;
     if(h[z-4]=='\r'&&h[z-3]=='\n'&&h[z-2]=='\r'&&h[z-1]=='\n')break;
    }
   }
   if(header.size()>=8192){send(out,"HTTP/1.1 431 Request Header Fields Too Large\r\n\r\n");return;}
   String first=new String(header.toByteArray(),StandardCharsets.ISO_8859_1).split("\\r?\\n",2)[0];
   String[] parts=first.split(" ");
   if(parts.length<3||!parts[0].equalsIgnoreCase("CONNECT")){send(out,"HTTP/1.1 405 Method Not Allowed\r\n\r\n");return;}
   String host;int port;
   try{
    String target=parts[1];
    if(target.startsWith("[")){int end=target.indexOf(']');host=target.substring(1,end);port=Integer.parseInt(target.substring(end+2));}
    else{int sep=target.lastIndexOf(':');host=target.substring(0,sep);port=Integer.parseInt(target.substring(sep+1));}
    if(host.isEmpty()||port<1||port>65535)throw new IllegalArgumentException();
   }catch(Exception e){send(out,"HTTP/1.1 400 Bad Request\r\n\r\n");return;}
   try(Socket remote=new Socket()){
    remote.connect(new InetSocketAddress(host,port),8000);
    remote.setSoTimeout(30000);c.setSoTimeout(30000);
    send(out,"HTTP/1.1 200 Connection Established\r\n\r\n");
    log("Connected: "+host+":"+port);
    Future<?> up=workers.submit(()->pipe(in,remote,true));
    pipe(remote.getInputStream(),c,false);
    try{up.get(2,TimeUnit.SECONDS);}catch(Exception ignored){}
   }
  }catch(Exception e){log("Connection ended: "+e.getClass().getSimpleName());}
  finally{active.decrementAndGet();log("Metrics updated");}
 }
 private void pipe(InputStream source,Socket target,boolean up){
  try{OutputStream dest=target.getOutputStream();byte[] buf=new byte[8192];int n;
   while((n=source.read(buf))!=-1){dest.write(buf,0,n);if(up)uploaded.addAndGet(n);else downloaded.addAndGet(n);}
  }catch(IOException ignored){}finally{try{target.shutdownOutput();}catch(IOException ignored){}}
 }
 private void send(OutputStream out,String s)throws IOException{out.write(s.getBytes(StandardCharsets.US_ASCII));out.flush();}
}