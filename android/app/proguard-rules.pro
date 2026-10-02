-keep class dev.mousevpn.app.NativeBridge { *; }
-keepclassmembers class dev.mousevpn.app.MouseVpnService {
    public boolean protectAndBindSocket(int);
    public boolean isConnectionCancelled(long);
}
