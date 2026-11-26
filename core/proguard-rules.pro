-keep class io.github.madeye.meow.core.MeowCore { *; }

# Called by name over JNI from meow-android-ffi's owner.rs.
-keepclassmembers class io.github.madeye.meow.bg.VpnService {
    int connectionOwnerUid(int, byte[], int, byte[], int);
    java.lang.String packageForUid(int);
    java.lang.String[] packagesForOverlayUid(int);
    byte[] resolveDirectDns(byte[]);
    void recordUnexpectedTunExit(int);
}

# Optional JNI class; absent in Lite.
-keep class io.github.madeye.meow.core.ZeroTierNative { *; }
