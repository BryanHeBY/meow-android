//! Private packet stack seam. The supervisor owns and polls all ports in
//! one task; the ports do not spawn, select policies, or manage the TUN FD.
use super::{AcceptedTcp, NetstackConn, UdpDatagram};
use futures::{SinkExt, StreamExt};
use std::io;

pub(super) struct Endpoint {
    pub(super) frames: Frames,
    pub(super) tcp: TcpIngress,
    pub(super) udp_tx: UdpEgress,
    pub(super) udp_rx: UdpIngress,
}

impl Endpoint {
    pub(super) fn open() -> io::Result<Self> {
        let (frames, tcp, udp) = lwip::NetStack::with_buffer_size(1024, 256)
            .map_err(|error| io::Error::other(error.to_string()))?;
        let (udp_tx, udp_rx) = udp.split();
        Ok(Self {
            frames: Frames(frames),
            tcp: TcpIngress(tcp),
            udp_tx: UdpEgress(udp_tx),
            udp_rx: UdpIngress(udp_rx),
        })
    }
}

pub(super) struct Frames(lwip::NetStack);

impl Frames {
    pub(super) async fn send(&mut self, raw: Vec<u8>) -> io::Result<()> {
        self.0.send(raw).await
    }

    pub(super) async fn receive(&mut self) -> Option<io::Result<Vec<u8>>> {
        self.0.next().await
    }
}

pub(super) struct TcpIngress(lwip::TcpListener);

impl TcpIngress {
    pub(super) async fn accept(
        &mut self,
    ) -> Option<AcceptedTcp<impl meow_common::ProxyConn + 'static>> {
        let (conn, src, dst) = self.0.next().await?;
        Some(AcceptedTcp {
            conn: NetstackConn(conn),
            src,
            dst,
        })
    }
}

pub(super) struct UdpIngress(lwip::UdpRecvHalf);

impl UdpIngress {
    pub(super) async fn receive(&mut self) -> Option<UdpDatagram> {
        let (payload, src, dst) = self.0.next().await?;
        Some(UdpDatagram { payload, src, dst })
    }
}

pub(super) struct UdpEgress(lwip::UdpSendHalf);

impl UdpEgress {
    pub(super) fn send(&self, datagram: &UdpDatagram) -> io::Result<()> {
        self.0
            .send_to(&datagram.payload, &datagram.src, &datagram.dst)
    }
}
