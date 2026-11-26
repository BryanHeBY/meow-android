//! Network exit for identified apps intentionally outside the Clash policy.
//! Socket authorization runs before connecting, and is separate from the
//! underlay hook the proxy transports and ZeroTier themselves use.
#[cfg(target_os = "android")]
use std::net::SocketAddr;
use std::net::{IpAddr, Ipv6Addr};

pub(crate) fn physical_destination(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, c, d] = v4.octets();
            !v4.is_loopback()
                && !v4.is_multicast()
                && !v4.is_broadcast()
                && a != 0
                && a != 28
                && !(a == 172 && b == 19 && c == 0 && d <= 3)
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return physical_destination(IpAddr::V4(v4));
            }
            !v6.is_unspecified()
                && !v6.is_multicast()
                && !v6.is_loopback()
                && v6.segments()[..3]
                    != Ipv6Addr::new(0xfdfe, 0xdcba, 0x9876, 0, 0, 0, 0, 0).segments()[..3]
        }
    }
}

#[cfg(target_os = "android")]
pub(crate) async fn tcp(mut stream: lwip::TcpStream, dst: SocketAddr) -> std::io::Result<()> {
    use std::{io, os::fd::AsRawFd, time::Duration};
    use tokio::net::TcpSocket;
    if !physical_destination(dst.ip()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "synthetic direct destination",
        ));
    }
    let socket = match dst {
        SocketAddr::V4(_) => TcpSocket::new_v4()?,
        SocketAddr::V6(_) => TcpSocket::new_v6()?,
    };
    crate::protect::direct(socket.as_raw_fd())?;
    let mut remote = tokio::time::timeout(Duration::from_secs(10), socket.connect(dst)).await??;
    tokio::io::copy_bidirectional(&mut stream, &mut remote).await?;
    Ok(())
}

#[cfg(any(target_os = "android", test))]
const DIRECT_UDP_RECEIVE_CAPACITY: usize = u16::MAX as usize;

#[cfg(any(target_os = "android", test))]
thread_local! {
    // Shared by flows on this runtime thread, rather than reserved per flow.
    static DIRECT_UDP_RECEIVE_SCRATCH: std::cell::RefCell<Vec<u8>> =
        std::cell::RefCell::new(vec![0; DIRECT_UDP_RECEIVE_CAPACITY]);
}

#[cfg(any(target_os = "android", test))]
fn poll_direct_udp_payload(
    cx: &mut std::task::Context<'_>,
    poll: impl FnOnce(
        &mut std::task::Context<'_>,
        &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>>,
) -> std::task::Poll<std::io::Result<Vec<u8>>> {
    DIRECT_UDP_RECEIVE_SCRATCH.with(|scratch| {
        let mut scratch = scratch.borrow_mut();
        let mut buf = tokio::io::ReadBuf::new(&mut scratch);
        // poll_recv cannot retain the ReadBuf on Pending. Copy on Ready so
        // neither the scratch nor its borrow crosses an await or task migration.
        poll(cx, &mut buf).map(|result| result.map(|()| buf.filled().to_vec()))
    })
}

#[cfg(target_os = "android")]
pub(crate) mod udp {
    use super::*;
    use parking_lot::Mutex;
    use std::{collections::HashMap, io, os::fd::AsRawFd, time::Duration};
    use tokio::{net::UdpSocket, sync::mpsc, task::JoinHandle};

    type Key = (SocketAddr, SocketAddr);
    type Datagram = (Vec<u8>, SocketAddr, SocketAddr);
    struct Flow {
        owner: Vec<String>,
        tx: mpsc::Sender<Vec<u8>>,
        task: JoinHandle<()>,
    }

    impl Drop for Flow {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    // The same physical socket must carry all datagrams in a flow, e.g. QUIC.
    // Bounded capacity, a short idle deadline and per-flow queues cap memory.
    #[derive(Default)]
    pub(crate) struct Flows(Mutex<HashMap<Key, Flow>>);

    impl Flows {
        pub fn transmit(
            &self,
            key: Key,
            owner: Vec<String>,
            data: Vec<u8>,
            reply: mpsc::Sender<Datagram>,
        ) {
            if !physical_destination(key.1.ip()) {
                return;
            }
            let mut flows = self.0.lock();
            if let Some(flow) = flows
                .get(&key)
                .filter(|f| !f.task.is_finished() && f.owner == owner)
            {
                let _ = flow.tx.try_send(data);
                return;
            }
            flows.remove(&key);
            flows.retain(|_, flow| !flow.task.is_finished());
            if flows.len() >= 256 {
                return;
            }
            let (tx, rx) = mpsc::channel(16);
            let _ = tx.try_send(data);
            let task_owner = owner.clone();
            let task = tokio::spawn(async move {
                let _ = run(key, task_owner, rx, reply).await;
            });
            flows.insert(key, Flow { owner, tx, task });
        }
    }

    fn protect(socket: &UdpSocket) -> io::Result<()> {
        crate::protect::direct(socket.as_raw_fd())
    }

    async fn run(
        key: Key,
        owner: Vec<String>,
        mut ingress: mpsc::Receiver<Vec<u8>>,
        reply: mpsc::Sender<Datagram>,
    ) -> io::Result<()> {
        let socket = match key.1 {
            SocketAddr::V4(_) => UdpSocket::bind("0.0.0.0:0").await?,
            SocketAddr::V6(_) => UdpSocket::bind("[::]:0").await?,
        };
        protect(&socket)?;
        socket.connect(key.1).await?;
        let ttl = Duration::from_secs(30);
        let idle = tokio::time::sleep(ttl);
        tokio::pin!(idle);
        loop {
            tokio::select! {
                data = ingress.recv() => {
                    let Some(data) = data else { return Ok(()) };
                    protect(&socket)?;
                    socket.send(&data).await?;
                    idle.as_mut().reset(tokio::time::Instant::now() + ttl);
                }
                payload = std::future::poll_fn(|cx| {
                    poll_direct_udp_payload(cx, |cx, buf| socket.poll_recv(cx, buf))
                }) => {
                    let payload = payload?;
                    let mut current = crate::owner::overlay_packages(crate::owner::IPPROTO_UDP, key.0, key.1).await;
                    current.sort_unstable();
                    current.dedup();
                    if current != owner {
                        return Ok(());
                    }
                    let _ = reply.try_send((payload, key.1, key.0));
                }
                () = &mut idle => return Ok(()),
            }
        }
    }
}

fn dns_query(payload: &[u8]) -> bool {
    (12..=4096).contains(&payload.len()) && payload[2] & 0x80 == 0 && payload[4..6] != [0, 0]
}

fn dns_response(query: &[u8], answer: &[u8]) -> bool {
    dns_query(query)
        && (12..=4096).contains(&answer.len())
        && answer[2] & 0x80 != 0
        && answer[..2] == query[..2]
}

#[cfg(target_os = "android")]
pub(crate) async fn system_dns(query: &[u8]) -> Option<Vec<u8>> {
    // The Java resolver blocks outside Tokio and is cancelled on timeout.
    if !dns_query(query) {
        return None;
    }
    static IN_FLIGHT: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(32);
    let permit = IN_FLIGHT.try_acquire().ok()?;
    let query = query.to_vec();
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        crate::protect::direct_dns(&query).filter(|answer| dns_response(&query, answer))
    })
    .await
    .ok()
    .flatten()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn direct_udp_scratch_is_released_between_flows_and_copies_payloads() {
        let first_packet = std::cell::RefCell::new(None::<Vec<u8>>);
        let mut first_read = std::future::poll_fn(|cx| {
            poll_direct_udp_payload(cx, |_, buf| match first_packet.borrow_mut().take() {
                Some(payload) => {
                    buf.put_slice(&payload);
                    std::task::Poll::Ready(Ok(()))
                }
                None => std::task::Poll::Pending,
            })
        });
        assert!(futures::poll!(&mut first_read).is_pending());
        // IPv4's largest UDP payload: 65,535 minus 20-byte IP and 8-byte UDP headers.
        let payload: Vec<_> = (0..65_507).map(|i| (i % 251) as u8).collect();
        let received = std::future::poll_fn(|cx| {
            poll_direct_udp_payload(cx, |_, buf| {
                buf.put_slice(&payload);
                std::task::Poll::Ready(Ok(()))
            })
        })
        .await
        .unwrap();
        *first_packet.borrow_mut() = Some(b"other flow".to_vec());
        assert_eq!(first_read.await.unwrap(), b"other flow");
        assert_eq!(received, payload);
        let empty = std::future::poll_fn(|cx| {
            poll_direct_udp_payload(cx, |_, _| std::task::Poll::Ready(Ok(())))
        })
        .await
        .unwrap();
        assert!(empty.is_empty());
    }

    #[tokio::test]
    async fn direct_udp_scratch_retains_the_full_previous_receive_capacity() {
        // Exercise the entire old 65,535-byte buffer, including IPv6's
        // 65,527-byte non-jumbogram UDP payload, without relying on MTU.
        for len in [65_527, DIRECT_UDP_RECEIVE_CAPACITY] {
            let payload: Vec<_> = (0..len).map(|i| (i % 251) as u8).collect();
            let received = std::future::poll_fn(|cx| {
                poll_direct_udp_payload(cx, |_, buf| {
                    assert_eq!(buf.remaining(), DIRECT_UDP_RECEIVE_CAPACITY);
                    buf.put_slice(&payload);
                    std::task::Poll::Ready(Ok(()))
                })
            })
            .await
            .unwrap();
            assert_eq!(received, payload);
        }
    }

    #[test]
    fn accepts_only_a_matching_dns_response_for_a_query() {
        let mut query = [0; 12];
        query[1] = 7;
        query[5] = 1;
        let mut answer = query;
        answer[2] = 0x80;
        assert!(dns_response(&query, &answer));
        assert!(!dns_response(&answer, &query));
        answer[0] = 1;
        assert!(!dns_response(&query, &answer));
        assert!(!dns_response(&query, &answer[..3]));
    }

    #[test]
    fn blocks_synthetic_reserved_and_ipv4_mapped_targets() {
        for addr in [
            "28.1.2.3",
            "172.19.0.2",
            "::ffff:28.1.2.3",
            "fdfe:dcba:9876::1",
            "::1",
            "127.0.0.2",
            "224.0.0.1",
            "0.0.0.0",
        ] {
            assert!(!physical_destination(addr.parse().unwrap()), "{addr}");
        }
        for addr in ["192.168.0.1", "2001:db8::1", "8.8.8.8"] {
            assert!(physical_destination(addr.parse().unwrap()), "{addr}");
        }
    }
}
