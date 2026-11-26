package io.github.madeye.meow.aidl;
import io.github.madeye.meow.aidl.IMeowServiceCallback;
import io.github.madeye.meow.aidl.SessionStats;
import io.github.madeye.meow.aidl.TrafficStats;

interface IMeowService {
    int getState();
    String getProfileName();
    void registerCallback(in IMeowServiceCallback cb);
    void startListeningForBandwidth(in IMeowServiceCallback cb, long timeout);
    void stopListeningForBandwidth(in IMeowServiceCallback cb);
    void unregisterCallback(in IMeowServiceCallback cb);

    // One proxy-detail probe through the named proxy of the running engine
    // (see the FFI crate's src/probe), or with an empty name through the
    // engine's routing. Blocks until the probe ends and returns its JSON
    // answer; cancelProxyProbe(id) ends it early.
    String probeProxy(long id, String proxy, String kind, String arg);
    oneway void cancelProxyProbe(long id);

    // Save the switch and apply it to a running engine (see src/live_dns.rs).
    // Returns null on success, else the transaction error.
    String setBuiltinDns(boolean enabled);

    // The running session's start time and its traffic per kind of network;
    // null while no engine is up.
    SessionStats getSessionStats();

    // Live forwarding controls. Must be called off the caller's main thread.
    int applyZeroTier();
    int setMeowForwarding(boolean enabled);
    int getForwardingFlags();
}
