package io.github.madeye.meow.aidl;
import io.github.madeye.meow.aidl.TrafficStats;
import io.github.madeye.meow.aidl.VpnServiceSnapshot;

interface IMeowServiceCallback {
    void stateChanged(in VpnServiceSnapshot snapshot, String msg);
    void trafficUpdated(long profileId, in TrafficStats stats);
    void trafficPersisted(long profileId);
    oneway void forwardingChanged(int flags);
}
