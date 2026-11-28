use super::{ipv4_header_checksum, start, stop};
use crate::test_support::{dns_query, from_the_profile_nameserver, txt_reply, SERIAL};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixDatagram;
use std::time::{Duration, Instant};

const APP_PORT: u16 = 42123;
const DNS_PORT: u16 = 53;
const LIMIT: Duration = Duration::from_secs(3);

struct PublishedResolver(Option<meow_dns::ResolverSlot>);

impl PublishedResolver {
    fn set(slot: meow_dns::ResolverSlot) -> Self {
        Self(crate::DNS_RESOLVER.write().replace(slot))
    }
}

impl Drop for PublishedResolver {
    fn drop(&mut self) {
        *crate::DNS_RESOLVER.write() = self.0.take();
    }
}

struct Upstream(tokio::task::JoinHandle<Vec<Vec<u8>>>);

impl Drop for Upstream {
    fn drop(&mut self) {
        self.0.abort();
    }
}

struct FakeTun {
    tun: UnixDatagram,
    app_port: u16,
    peer: UnixDatagram,
    app: IpAddr,
    dns: IpAddr,
}

impl FakeTun {
    fn open(app: IpAddr, dns: IpAddr) -> Self {
        let (tun, peer) = UnixDatagram::pair().unwrap();
        peer.set_read_timeout(Some(LIMIT)).unwrap();
        start(tun.as_raw_fd(), 0).unwrap();
        Self {
            tun,
            app_port: APP_PORT,
            peer,
            app,
            dns,
        }
    }

    fn restart(&mut self) {
        assert!(
            stop(),
            "previous worker must join before restarting the same FD"
        );
        // The peer queue can still contain ACKs for the first flow. A
        // different source port makes that traffic ineligible for the next
        // handshake rather than assuming the queue was flushed by stop.
        self.app_port += 1;
        start(self.tun.as_raw_fd(), 0).unwrap();
    }

    fn send_tcp(&self, seq: u32, ack: u32, flags: u8, payload: &[u8]) {
        let mut tcp = vec![0; 20];
        tcp[..2].copy_from_slice(&self.app_port.to_be_bytes());
        tcp[2..4].copy_from_slice(&DNS_PORT.to_be_bytes());
        tcp[4..8].copy_from_slice(&seq.to_be_bytes());
        tcp[8..12].copy_from_slice(&ack.to_be_bytes());
        tcp[12] = 0x50; // No TCP options.
        tcp[13] = flags;
        tcp[14..16].copy_from_slice(&u16::MAX.to_be_bytes());
        tcp.extend_from_slice(payload);

        let tcp_len = u16::try_from(tcp.len()).unwrap();
        let (mut packet, mut pseudo) = match (self.app, self.dns) {
            (IpAddr::V4(src), IpAddr::V4(dst)) => {
                let mut ip = vec![0; 20];
                ip[0] = 0x45;
                ip[2..4].copy_from_slice(&(20 + tcp_len).to_be_bytes());
                ip[8] = 64;
                ip[9] = 6;
                ip[12..16].copy_from_slice(&src.octets());
                ip[16..20].copy_from_slice(&dst.octets());
                let sum = ipv4_header_checksum(&ip);
                ip[10..12].copy_from_slice(&sum.to_be_bytes());
                let pseudo = [
                    src.octets().as_slice(),
                    dst.octets().as_slice(),
                    &[0, 6],
                    tcp_len.to_be_bytes().as_slice(),
                ]
                .concat();
                (ip, pseudo)
            }
            (IpAddr::V6(src), IpAddr::V6(dst)) => {
                let mut ip = vec![0; 40];
                ip[0] = 0x60;
                ip[4..6].copy_from_slice(&tcp_len.to_be_bytes());
                ip[6] = 6;
                ip[7] = 64;
                ip[8..24].copy_from_slice(&src.octets());
                ip[24..40].copy_from_slice(&dst.octets());
                let pseudo = [
                    src.octets().as_slice(),
                    dst.octets().as_slice(),
                    u32::from(tcp_len).to_be_bytes().as_slice(),
                    &[0, 0, 0, 6],
                ]
                .concat();
                (ip, pseudo)
            }
            _ => panic!("test addresses must have the same family"),
        };
        pseudo.extend_from_slice(&tcp);
        let sum = ipv4_header_checksum(&pseudo);
        tcp[16..18].copy_from_slice(&sum.to_be_bytes());
        packet.extend(tcp);
        assert_eq!(self.peer.send(&packet).unwrap(), packet.len());
    }

    fn receive_tcp(&self, deadline: Instant) -> io::Result<TcpSegment> {
        let mut packet = [0; 2048];
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(io::ErrorKind::TimedOut.into());
            }
            self.peer.set_read_timeout(Some(remaining)).unwrap();
            let len = self.peer.recv(&mut packet)?;
            let ip_end = match packet[0] >> 4 {
                4 if len >= 40 && packet[9] == 6 && self.dns.is_ipv4() => {
                    let src: [u8; 4] = packet[12..16].try_into().unwrap();
                    let dst: [u8; 4] = packet[16..20].try_into().unwrap();
                    assert_eq!(IpAddr::from(Ipv4Addr::from(src)), self.dns);
                    assert_eq!(IpAddr::from(Ipv4Addr::from(dst)), self.app);
                    usize::from(packet[0] & 15) * 4
                }
                6 if len >= 60 && packet[6] == 6 && self.dns.is_ipv6() => {
                    let src: [u8; 16] = packet[8..24].try_into().unwrap();
                    let dst: [u8; 16] = packet[24..40].try_into().unwrap();
                    assert_eq!(IpAddr::from(Ipv6Addr::from(src)), self.dns);
                    assert_eq!(IpAddr::from(Ipv6Addr::from(dst)), self.app);
                    40
                }
                _ => continue,
            };
            let tcp = &packet[ip_end..len];
            if tcp.len() < 20
                || tcp[..2] != DNS_PORT.to_be_bytes()
                || tcp[2..4] != self.app_port.to_be_bytes()
            {
                continue;
            }
            let tcp_end = usize::from(tcp[12] >> 4) * 4;
            return Ok(TcpSegment {
                seq: u32::from_be_bytes(tcp[4..8].try_into().unwrap()),
                flags: tcp[13],
                payload: tcp[tcp_end..].to_vec(),
            });
        }
    }
}

impl Drop for FakeTun {
    fn drop(&mut self) {
        stop();
    }
}

struct TcpSegment {
    seq: u32,
    flags: u8,
    payload: Vec<u8>,
}

fn dns_frame(id: u16, name: &str) -> Vec<u8> {
    let mut query = dns_query(name, 16);
    query[..2].copy_from_slice(&id.to_be_bytes());
    let mut frame = u16::try_from(query.len()).unwrap().to_be_bytes().to_vec();
    frame.extend(query);
    frame
}

fn exchange_over_fake_tun(tun: &FakeTun, requests: [(u16, &str); 2]) -> io::Result<Vec<Vec<u8>>> {
    let mut tx = 1u32;
    tun.send_tcp(tx, 0, 0x02, &[]);
    tx += 1;
    let syn_ack = tun.receive_tcp(Instant::now() + LIMIT)?;
    assert_eq!(syn_ack.flags & 0x12, 0x12, "TUN must accept TCP SYN");
    let mut rx = syn_ack.seq.wrapping_add(1);
    tun.send_tcp(tx, rx, 0x10, &[]);

    let [(first_id, first_name), (second_id, second_name)] = requests;
    let first = dns_frame(first_id, first_name);
    let second = dns_frame(second_id, second_name);
    // Split the first length prefix; coalesce the remainder with another
    // request on the same stream. The lwIP packet boundaries are not frames.
    let (head, rest) = first.split_at(1);
    let tail = [rest, &second].concat();
    for bytes in [head, tail.as_slice()] {
        tun.send_tcp(tx, rx, 0x18, bytes);
        tx = tx.wrapping_add(u32::try_from(bytes.len()).unwrap());
    }

    let deadline = Instant::now() + LIMIT;
    let mut data = Vec::new();
    let mut frames = Vec::new();
    while frames.len() < 2 {
        let msg = tun.receive_tcp(deadline)?;
        if msg.flags & 0x05 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                "TUN closed the accepted port-53 flow before framed DNS replies",
            ));
        }
        if msg.payload.is_empty() {
            continue;
        }
        assert_eq!(msg.seq, rx, "ordered loopback TUN TCP reply");
        rx = rx.wrapping_add(u32::try_from(msg.payload.len()).unwrap());
        tun.send_tcp(tx, rx, 0x10, &[]);
        data.extend(msg.payload);
        while let [high, low, ..] = data[..] {
            let n = usize::from(u16::from_be_bytes([high, low]));
            assert!(n >= 12, "invalid DNS TCP response length {n}");
            if data.len() < n + 2 {
                break;
            }
            frames.push(data[2..n + 2].to_vec());
            data.drain(..n + 2);
        }
    }
    assert!(data.is_empty(), "unexpected unframed trailing DNS bytes");
    Ok(frames)
}

#[test]
fn tun_tcp_dns_uses_live_resolver_for_split_and_repeated_queries() {
    check_dns_round_trip("172.19.0.1", "172.19.0.2");
}

#[test]
fn tun_tcp_dns_intercepts_ipv6_when_hijack_is_enabled() {
    check_dns_round_trip("2001:db8::1", "2001:db8::53");
}

fn check_dns_round_trip(app: &str, dns: &str) {
    let _serial = SERIAL.lock();
    let rt = crate::get_runtime();
    let server = rt
        .block_on(tokio::net::UdpSocket::bind("127.0.0.1:0"))
        .unwrap();
    let local = server.local_addr().unwrap();
    let exchanges = [
        [(0xb123u16, "first.invalid"), (0xb124, "second.invalid")],
        [
            (0xb223, "restart-first.invalid"),
            (0xb224, "restart-second.invalid"),
        ],
    ];
    let query_count = exchanges.iter().flatten().count();
    let mut upstream = Upstream(rt.spawn(async move {
        let mut seen = Vec::new();
        let mut buf = [0; 512];
        for _ in 0..query_count {
            let (n, sender) = server.recv_from(&mut buf).await.unwrap();
            seen.push(buf[..n].to_vec());
            server
                .send_to(&txt_reply(&buf[..n]).unwrap(), sender)
                .await
                .unwrap();
        }
        seen
    }));

    let yaml = format!(
        "dns:\n  enable: true\n  nameserver: ['udp://{local}']\n  default-nameserver: ['udp://{local}']\nrules: ['MATCH,DIRECT']\n"
    );
    let config = rt
        .block_on(meow_config::load_config_from_str(&yaml))
        .unwrap();
    let _resolver = PublishedResolver::set(config.dns.resolver_slot);
    let mut tun = FakeTun::open(app.parse().unwrap(), dns.parse().unwrap());
    let mut replies = exchange_over_fake_tun(&tun, exchanges[0])
        .expect("VPN DNS TCP/53 must reach the published resolver before restart");
    tun.restart();
    replies.extend(
        exchange_over_fake_tun(&tun, exchanges[1])
            .expect("VPN DNS TCP/53 must reach the published resolver after same-FD restart"),
    );
    drop(tun);
    let seen = rt
        .block_on(async { tokio::time::timeout(LIMIT, &mut upstream.0).await })
        .unwrap()
        .unwrap();
    assert_eq!(seen.len(), query_count);
    assert_eq!(replies.len(), query_count);
    for ((reply, query), (id, name)) in replies
        .iter()
        .zip(seen)
        .zip(exchanges.into_iter().flatten())
    {
        assert_eq!(reply[..2], id.to_be_bytes());
        assert_eq!(reply[2] & 0x82, 0x80, "complete response, not a TC reply");
        let label = name.split('.').next().unwrap().as_bytes();
        assert_eq!(usize::from(query[12]), label.len());
        assert_eq!(&query[13..13 + label.len()], label);
        assert!(from_the_profile_nameserver(reply));
    }
}

#[test]
fn dns_hijack_does_not_capture_encrypted_dns_ports_or_change_upstream_transports() {
    use super::DnsHijackPolicy;
    use crate::engine::{strip_and_inject, DnsUpstreams};

    let enabled = DnsHijackPolicy::new(true);
    let disabled = DnsHijackPolicy::new(false);
    let vpn = "172.19.0.2:53".parse().unwrap();
    assert!(enabled.captures(vpn));
    assert!(disabled.captures(vpn));
    for destination in ["192.0.2.53:53", "[2001:db8::53]:53"] {
        let address = destination.parse().unwrap();
        assert!(enabled.captures(address));
        assert!(!disabled.captures(address));
    }
    for destination in [
        "172.19.0.2:443",
        "172.19.0.2:853",
        "192.0.2.53:443",
        "192.0.2.53:853",
        "[2001:db8::53]:443",
        "[2001:db8::53]:853",
    ] {
        let address = destination.parse().unwrap();
        assert!(!enabled.captures(address));
        assert!(!disabled.captures(address));
    }

    // Normalize offline only. The ingress switch belongs to a VPN session,
    // not the author's resolver plan for encrypted outbound DNS.
    let profile = r#"
dns:
  nameserver: ["https://192.0.2.53/dns-query", "tls://[2001:db8::53]:853"]
  default-nameserver: ["udp://192.0.2.54:53"]
rules: ["MATCH,DIRECT"]
"#;
    let authored: serde_yaml::Value = serde_yaml::from_str(profile).unwrap();
    let normalized = strip_and_inject(profile, DnsUpstreams::Profile).unwrap();
    let actual: serde_yaml::Value = serde_yaml::from_str(&normalized).unwrap();
    for key in ["nameserver", "default-nameserver"] {
        assert_eq!(actual["dns"][key], authored["dns"][key], "{key}");
    }
}
