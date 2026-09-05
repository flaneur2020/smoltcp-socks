use super::*;
use crate::device::DeviceHandles;
use smoltcp::phy::ChecksumCapabilities;
use smoltcp::wire::{
    IpProtocol, Ipv4Packet, Ipv4Repr, TcpControl, TcpPacket, TcpRepr, TcpSeqNumber,
};

struct Connection {
    iface: Interface,
    phy: Phy,
    sockets: SocketSet<'static>,
    handle: SocketHandle,
    device: DeviceHandles,
    server_seq: TcpSeqNumber,
}

impl Connection {
    fn new() -> Self {
        let (mut phy, device) = Phy::new(1500);
        let iface = super::super::build_interface(&mut phy);
        let mut sockets = SocketSet::new(vec![]);
        let mut socket = super::super::new_tcp_socket(8, 4);
        socket.listen(IpListenEndpoint::ANY_PORT).unwrap();
        let handle = sockets.add(socket);
        let mut conn = Self {
            iface,
            phy,
            sockets,
            handle,
            device,
            server_seq: TcpSeqNumber(0),
        };
        conn.send(TcpControl::Syn, 100, None, &[]);
        let synack = conn.device.outbound.try_recv().unwrap();
        let ip = Ipv4Packet::new_checked(&synack).unwrap();
        let tcp = TcpPacket::new_checked(ip.payload()).unwrap();
        conn.server_seq = tcp.seq_number();
        conn.send(TcpControl::None, 101, Some(conn.server_seq + 1), &[]);
        assert_eq!(conn.socket().state(), State::Established);
        conn
    }

    fn socket(&mut self) -> &mut TcpSocket<'static> {
        self.sockets.get_mut::<TcpSocket>(self.handle)
    }

    fn send(&mut self, control: TcpControl, seq: i32, ack: Option<TcpSeqNumber>, payload: &[u8]) {
        let tcp = TcpRepr {
            src_port: 50000,
            dst_port: 443,
            control,
            seq_number: TcpSeqNumber(seq),
            ack_number: ack,
            window_len: 4096,
            window_scale: None,
            max_seg_size: None,
            sack_permitted: false,
            sack_ranges: [None; 3],
            timestamp: None,
            payload,
        };
        let ip = Ipv4Repr {
            src_addr: "10.0.0.2".parse().unwrap(),
            dst_addr: "203.0.113.1".parse().unwrap(),
            next_header: IpProtocol::Tcp,
            payload_len: tcp.buffer_len(),
            hop_limit: 64,
        };
        let caps = ChecksumCapabilities::default();
        let mut packet = vec![0; ip.buffer_len() + tcp.buffer_len()];
        ip.emit(
            &mut Ipv4Packet::new_unchecked(&mut packet[..ip.buffer_len()]),
            &caps,
        );
        tcp.emit(
            &mut TcpPacket::new_unchecked(&mut packet[ip.buffer_len()..]),
            &ip.src_addr.into(),
            &ip.dst_addr.into(),
            &caps,
        );
        self.device.inbound.try_send(packet).unwrap();
        self.iface
            .poll(Instant::now(), &mut self.phy, &mut self.sockets);
    }
}

#[tokio::test]
async fn pending_read_and_write_resume_independently() {
    let mut conn = Connection::new();
    let (tx, rx) = mpsc::channel(8);
    let mut state = ConnState::new(rx);
    assert_eq!(conn.socket().send_slice(b"full"), Ok(4));

    let (read_tx, mut read_rx) = oneshot::channel();
    let (write_tx, mut write_rx) = oneshot::channel();
    tx.try_send(ConnCmd::Read {
        max_len: 8,
        reply: read_tx,
    })
    .unwrap();
    tx.try_send(ConnCmd::Write {
        data: b"!".to_vec(),
        reply: write_tx,
    })
    .unwrap();
    state.service(conn.socket());
    assert!(matches!(
        read_rx.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));
    assert!(matches!(
        write_rx.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));

    conn.send(TcpControl::None, 101, Some(conn.server_seq + 1), b"ping");
    state.service(conn.socket());
    assert_eq!(read_rx.await.unwrap().unwrap(), b"ping");
    assert!(matches!(
        write_rx.try_recv(),
        Err(oneshot::error::TryRecvError::Empty)
    ));

    conn.send(TcpControl::None, 105, Some(conn.server_seq + 5), &[]);
    state.service(conn.socket());
    assert_eq!(write_rx.await.unwrap().unwrap(), 1);
}

#[tokio::test]
async fn partial_write_and_empty_io_complete() {
    let mut conn = Connection::new();
    let (tx, rx) = mpsc::channel(8);
    let mut state = ConnState::new(rx);
    let (write_tx, write_rx) = oneshot::channel();
    tx.try_send(ConnCmd::Write {
        data: b"abcdef".to_vec(),
        reply: write_tx,
    })
    .unwrap();
    state.service(conn.socket());
    assert_eq!(write_rx.await.unwrap().unwrap(), 4);

    let (read_tx, read_rx) = oneshot::channel();
    let (write_tx, write_rx) = oneshot::channel();
    tx.try_send(ConnCmd::Read {
        max_len: 0,
        reply: read_tx,
    })
    .unwrap();
    tx.try_send(ConnCmd::Write {
        data: vec![],
        reply: write_tx,
    })
    .unwrap();
    state.service(conn.socket());
    assert!(read_rx.await.unwrap().unwrap().is_empty());
    assert_eq!(write_rx.await.unwrap().unwrap(), 0);
}

#[tokio::test]
async fn close_resolves_both_pending_directions() {
    let mut conn = Connection::new();
    let (tx, rx) = mpsc::channel(8);
    let mut state = ConnState::new(rx);
    conn.socket().send_slice(b"full").unwrap();
    let (read_tx, read_rx) = oneshot::channel();
    let (write_tx, write_rx) = oneshot::channel();
    let (close_tx, close_rx) = oneshot::channel();
    tx.try_send(ConnCmd::Read {
        max_len: 8,
        reply: read_tx,
    })
    .unwrap();
    tx.try_send(ConnCmd::Write {
        data: b"!".to_vec(),
        reply: write_tx,
    })
    .unwrap();
    tx.try_send(ConnCmd::Close { reply: close_tx }).unwrap();
    state.service(conn.socket());
    assert!(close_rx.await.unwrap().is_ok());
    assert!(matches!(read_rx.await.unwrap(), Err(VConnError::Closed)));
    assert!(matches!(write_rx.await.unwrap(), Err(VConnError::Closed)));
}

#[tokio::test]
async fn half_close_preserves_pending_read() {
    let mut conn = Connection::new();
    let (tx, rx) = mpsc::channel(8);
    let mut state = ConnState::new(rx);
    let (read_tx, read_rx) = oneshot::channel();
    let (close_tx, close_rx) = oneshot::channel();
    tx.try_send(ConnCmd::Read {
        max_len: 8,
        reply: read_tx,
    })
    .unwrap();
    tx.try_send(ConnCmd::CloseWrite { reply: close_tx })
        .unwrap();
    state.service(conn.socket());
    assert!(close_rx.await.unwrap().is_ok());
    assert!(conn.socket().may_recv());
    conn.send(TcpControl::None, 101, Some(conn.server_seq + 1), b"reply");
    state.service(conn.socket());
    assert_eq!(read_rx.await.unwrap().unwrap(), b"reply");
}

#[tokio::test]
async fn accept_connection_already_half_closed_by_client() {
    let mut conn = Connection::new();
    conn.send(TcpControl::Fin, 101, Some(conn.server_seq + 1), b"hello");
    assert_eq!(conn.socket().state(), State::CloseWait);
    let (accepted_tx, mut accepted_rx) = mpsc::channel(8);
    let (_stop_tx, stop) = mpsc::channel(1);
    let mut actor = NetstackActor {
        iface: conn.iface,
        phy: conn.phy,
        sockets: conn.sockets,
        conns: HashMap::new(),
        listeners: vec![conn.handle],
        accepted_tx,
        stop,
    };
    actor.try_accept();
    let (_, meta) = accepted_rx.try_recv().unwrap();
    assert_eq!(meta.dst, "203.0.113.1:443".parse().unwrap());
    assert_eq!(actor.conns.len(), 1);
    let mut data = [0; 8];
    let socket = actor.sockets.get_mut::<TcpSocket>(conn.handle);
    assert_eq!(socket.recv_slice(&mut data), Ok(5));
    assert_eq!(&data[..5], b"hello");
    assert_eq!(socket.recv_slice(&mut data), Err(RecvError::Finished));
    assert_eq!(
        actor.sockets.get::<TcpSocket>(actor.listeners[0]).state(),
        State::Listen
    );
}
