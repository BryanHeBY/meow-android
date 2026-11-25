package io.github.meowz.policymatrix;

import android.app.Activity;
import android.os.Bundle;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/** Disposable emulator probe: packets originate from this APK's own UID, not adb shell. */
public final class ProbeActivity extends Activity {
    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        final String host = getIntent().getStringExtra("host");
        final String method = getIntent().getStringExtra("method");
        final String nonce = getIntent().getStringExtra("nonce");
        final int port = getIntent().getIntExtra("port", -1);
        // Accept only the disposable AVD host and the fixture's overlay member.
        if (!("10.0.2.2".equals(host) || "10.203.0.1".equals(host))
                || !("tcp".equals(method) || "udp".equals(method))
                || nonce == null || !nonce.matches("[a-zA-Z0-9_-]{1,40}")
                || port < 1024 || port > 65535) {
            finish();
            return;
        }
        new Thread(() -> {
            String result;
            try {
                byte[] message = (getPackageName() + ":" + nonce).getBytes(StandardCharsets.US_ASCII);
                final InetSocketAddress destination = new InetSocketAddress(host, port);
                byte[] response;
                if ("udp".equals(method)) {
                    try (DatagramSocket udp = new DatagramSocket()) {
                        udp.connect(destination);
                        udp.setSoTimeout(2500);
                        udp.send(new DatagramPacket(message, message.length));
                        DatagramPacket incoming = new DatagramPacket(new byte[128], 128);
                        udp.receive(incoming);
                        response = Arrays.copyOf(incoming.getData(), incoming.getLength());
                    }
                } else {
                    try (Socket tcp = new Socket()) {
                        tcp.connect(destination, 2500);
                        tcp.setSoTimeout(2500);
                        tcp.getOutputStream().write(message);
                        tcp.shutdownOutput();
                        byte[] data = new byte[128];
                        int length = tcp.getInputStream().read(data);
                        response = Arrays.copyOf(data, Math.max(0, length));
                    }
                }
                result = Arrays.equals(message, response) ? "echo" : "invalid-response";
            } catch (IOException e) {
                result = e.getClass().getSimpleName();
            }
            try (var file = openFileOutput("probe-" + nonce, MODE_PRIVATE)) {
                file.write(result.getBytes(StandardCharsets.US_ASCII));
            } catch (IOException ignored) { }
            runOnUiThread(this::finish);
        }, "meowz-policy-test").start();
    }
}
