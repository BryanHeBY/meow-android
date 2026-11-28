use super::{ipv4_header_checksum, start, stop};
use crate::test_support::{dns_query, from_the_profile_nameserver, txt_reply, SERIAL};
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixDatagram;
use std::time::{Duration, Instant};

const APP: [u8; 4] = [172, 19, 0, 1];
const VPN_DNS: [u8; 4] = [172, 19, 0, 2];
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
    _tun: UnixDatagram,
    peer: UnixDatagram,
}

impl FakeTun {
    fn open() -> Self {
        let (tun, peer) = UnixDatagram::pair().unwrap();
        peer.set_read_timeout(Some(LIMIT)).unwrap();
        start(tun.as_raw_fd(), 0).unwrap();
        Self { _tun: tun, peer }
    }

    fn send_tcp(&self, seq: u32, ack: u32, flags: u8, payload: &[u8]) {
        let total = u16::try_from(40 + payload.len()).unwrap();
        let mut packet = vec![0; usize::from(total)];
        packet[0] = 0x45;
        packet[2..4].copy_from_slice(&total.to_be_bytes());
        packet[8] = 64;
        packet[9] = 6;
        packet[12..16].copy_from_slice(&APP);
        packet[16..20].copy_from_slice(&VPN_DNS);
        let sum = ipv4_header_checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&sum.to_be_bytes());

        packet[20..22].copy_from_slice(&APP_PORT.to_be_bytes());
        packet[22..24].copy_from_slice(&DNS_PORT.to_be_bytes());
        packet[24..28].copy_from_slice(&seq.to_be_bytes());
        packet[28..32].copy_from_slice(&ack.to_be_bytes());
        packet[32] = 0x50; // No TCP options.
        packet[33] = flags;
        packet[34..36].copy_from_slice(&u16::MAX.to_be_bytes());
        packet[40..].copy_from_slice(payload);
        let mut pseudo = [APP.as_slice(), VPN_DNS.as_slice(), &[0, 6]].concat();
        pseudo.extend_from_slice(&(total - 20).to_be_bytes());
        pseudo.extend_from_slice(&packet[20..]);
        let sum = ipv4_header_checksum(&pseudo);
        packet[36..38].copy_from_slice(&sum.to_be_bytes());
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
            if len < 40 || packet[0] >> 4 != 4 || packet[9] != 6 {
                continue;
            }
            let ip_end = usize::from(packet[0] & 15) * 4;
            let tcp = &packet[ip_end..len];
            if tcp.len() < 20
                || tcp[..2] != DNS_PORT.to_be_bytes()
                || tcp[2..4] != APP_PORT.to_be_bytes()
            {
                continue;
            }
            assert_eq!(packet[12..16], VPN_DNS);
            assert_eq!(packet[16..20], APP);
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

fn exchange_over_fake_tun(tun: &FakeTun) -> io::Result<Vec<Vec<u8>>> {
    let mut tx = 1u32;
    tun.send_tcp(tx, 0, 0x02, &[]);
    tx += 1;
    let syn_ack = tun.receive_tcp(Instant::now() + LIMIT)?;
    assert_eq!(syn_ack.flags & 0x12, 0x12, "TUN must accept TCP SYN");
    let mut rx = syn_ack.seq.wrapping_add(1);
    tun.send_tcp(tx, rx, 0x10, &[]);

    let first = dns_frame(0xb123, "first.invalid");
    let second = dns_frame(0xb124, "second.invalid");
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
    let _serial = SERIAL.lock();
    let rt = crate::get_runtime();
    let server = rt
        .block_on(tokio::net::UdpSocket::bind("127.0.0.1:0"))
        .unwrap();
    let local = server.local_addr().unwrap();
    let mut upstream = Upstream(rt.spawn(async move {
        let mut seen = Vec::new();
        let mut buf = [0; 512];
        for _ in 0..2 {
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
        "dns:\n  nameserver: ['udp://{local}']\n  default-nameserver: ['udp://{local}']\nrules: ['MATCH,DIRECT']\n"
    );
    let config = rt
        .block_on(meow_config::load_config_from_str(&yaml))
        .unwrap();
    let _resolver = PublishedResolver::set(config.dns.resolver_slot);
    let tun = FakeTun::open();
    let result = exchange_over_fake_tun(&tun);
    drop(tun);
    let replies = result.expect("VPN DNS TCP/53 must reach the published resolver");
    let seen = rt
        .block_on(async { tokio::time::timeout(LIMIT, &mut upstream.0).await })
        .unwrap()
        .unwrap();
    assert_eq!(seen.len(), 2);
    for ((reply, query), (id, name)) in replies
        .iter()
        .zip(seen)
        .zip([(0xb123u16, b"first".as_slice()), (0xb124, b"second")])
    {
        assert_eq!(reply[..2], id.to_be_bytes());
        assert_eq!(reply[2] & 0x82, 0x80, "complete response, not a TC reply");
        assert!(query.windows(name.len()).any(|word| word == name));
        assert!(from_the_profile_nameserver(reply));
    }
}
