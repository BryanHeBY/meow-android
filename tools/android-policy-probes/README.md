# Independent Android app probes

Use only on a disposable Android 29+ emulator. These are test tools,
not application modules or packages to distribute. The fixture validates
both TCP and UDP with application sockets and distinct Android package UIDs.

Build using JDK 17, Python 3, and the SDK's Android 36 platform and
36.0.0 build tools:

```sh
ANDROID_HOME=/path/to/sdk tools/android-policy-probes/build-probes.sh /tmp/policy-probes
```

Install both emitted APKs on an explicitly selected emulator serial.
Confirm the packages have different UIDs with `pm list packages -U
io.github.meowz.policymatrix`. Operate each one independently:

```sh
package=io.github.meowz.policymatrix.a  # or .b
adb -s emulator-5554 shell am start -W \
  -n "$package/io.github.meowz.policymatrix.ProbeActivity" \
  --es method udp --es host 10.0.2.2 --ei port 27938 --es nonce test-a
adb -s emulator-5554 shell run-as "$package" cat files/probe-test-a
```

Use a fresh nonce for each run. Allowed addresses are the emulator host
alias (10.0.2.2) and the private overlay fixture (10.203.0.1). The service
should echo the original payload on the same connection and log the nonce
so that each lane can be distinguished independently of the app result.
Prove ordinary no-VPN TCP and UDP work for both apps before passing
judgment on any denied path. Use a separate endpoint or proxy log to
distinguish protected direct traffic from Clash traffic. A timeout alone
does not show which lane was attempted.
