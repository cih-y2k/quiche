// Copyright (C) 2019, Cloudflare, Inc.
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are
// met:
//
//     * Redistributions of source code must retain the above copyright notice,
//       this list of conditions and the following disclaimer.
//
//     * Redistributions in binary form must reproduce the above copyright
//       notice, this list of conditions and the following disclaimer in the
//       documentation and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS
// IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
// PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
// CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
// EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
// PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
// PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
// LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
// NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
// SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

#[macro_use]
extern crate log;

use std::net;

use std::collections::HashMap;

use ring::rand::*;

const LOCAL_CONN_ID_LEN: usize = 16;

const MAX_DATAGRAM_SIZE: usize = 1452;

const USAGE: &str = "Usage:
  h3server [options]
  h3server -h | --help

Options:
  --listen <addr>   Listen on the given IP:port [default: 127.0.0.1:4433]
  --cert <file>     TLS certificate path [default: examples/cert.crt]
  --key <file>      TLS certificate key path [default: examples/cert.key]
  --root <dir>      Root directory [default: examples/root/]
  --name <str>      Name of the server [default: quic.tech]
  -h --help         Show this screen.
";
type QuicH3Conn = (Box<quiche::Connection>, Option<quiche::h3::Connection>);

type ConnMap = HashMap<Vec<u8>, (net::SocketAddr, QuicH3Conn)>;

fn main() {
    let mut buf = [0; 65535];
    let mut out = [0; MAX_DATAGRAM_SIZE];

    env_logger::init();

    let args = docopt::Docopt::new(USAGE)
        .and_then(|dopt| dopt.parse())
        .unwrap_or_else(|e| e.exit());

    let socket = net::UdpSocket::bind(args.get_str("--listen")).unwrap();

    let poll = mio::Poll::new().unwrap();
    let mut events = mio::Events::with_capacity(1024);

    let socket = mio::net::UdpSocket::from_socket(socket).unwrap();
    poll.register(
        &socket,
        mio::Token(0),
        mio::Ready::readable(),
        mio::PollOpt::edge(),
    )
    .unwrap();

    let mut connections = ConnMap::new();

    let mut quiche_config = quiche::Config::new(quiche::VERSION_DRAFT17).unwrap();

    quiche_config
        .load_cert_chain_from_pem_file(args.get_str("--cert"))
        .unwrap();
    quiche_config
        .load_priv_key_from_pem_file(args.get_str("--key"))
        .unwrap();

    quiche_config
        .set_application_protos(&[b"h3-17", b"hq-17", b"http/0.9"])
        .unwrap();

    quiche_config.set_idle_timeout(30);
    quiche_config.set_max_packet_size(MAX_DATAGRAM_SIZE as u64);
    quiche_config.set_initial_max_data(10_000_000);
    quiche_config.set_initial_max_stream_data_bidi_local(1_000_000);
    quiche_config.set_initial_max_stream_data_bidi_remote(1_000_000);
    quiche_config.set_initial_max_streams_bidi(100);
    quiche_config.set_initial_max_streams_uni(100);
    quiche_config.set_disable_migration(true);

    loop {
        // TODO: use event loop that properly supports timers
        let timeout = connections
            .values()
            .filter_map(|(_, c)| c.0.timeout())
            .min();

        poll.poll(&mut events, timeout).unwrap();

        'read: loop {
            if events.is_empty() {
                debug!("timed out");

                connections.values_mut().for_each(|(_, c)| c.0.on_timeout());

                break 'read;
            }

            let (len, src) = match socket.recv_from(&mut buf) {
                Ok(v) => v,

                Err(e) => {
                    if e.kind() == std::io::ErrorKind::WouldBlock {
                        debug!("recv() would block");
                        break 'read;
                    }

                    panic!("recv() failed: {:?}", e);
                },
            };

            debug!("got {} bytes", len);

            let buf = &mut buf[..len];

            let hdr = match quiche::Header::from_slice(buf, LOCAL_CONN_ID_LEN) {
                Ok(v) => v,

                Err(e) => {
                    error!("Parsing packet header failed: {:?}", e);
                    continue;
                },
            };

            if hdr.ty == quiche::Type::VersionNegotiation {
                error!("Version negotiation invalid on the server");
                continue;
            }

            let (_, quich3_conn) = if !connections.contains_key(&hdr.dcid) {
                if hdr.ty != quiche::Type::Initial {
                    error!("Packet is not Initial");
                    continue;
                }

                if hdr.version != quiche::VERSION_DRAFT17 {
                    warn!("Doing version negotiation");

                    let len =
                        quiche::negotiate_version(&hdr.scid, &hdr.dcid, &mut out)
                            .unwrap();
                    let out = &out[..len];

                    socket.send_to(out, &src).unwrap();
                    continue;
                }

                let mut scid: [u8; LOCAL_CONN_ID_LEN] = [0; LOCAL_CONN_ID_LEN];
                SystemRandom::new().fill(&mut scid[..]).unwrap();

                // Token is always present in Initial packets.
                let token = hdr.token.as_ref().unwrap();

                if token.is_empty() {
                    warn!("Doing stateless retry");

                    let new_token = mint_token(&hdr, &src);

                    let len = quiche::retry(
                        &hdr.scid, &hdr.dcid, &scid, &new_token, &mut out,
                    )
                    .unwrap();
                    let out = &out[..len];

                    socket.send_to(out, &src).unwrap();
                    continue;
                }

                let odcid = validate_token(&src, token);

                if odcid == None {
                    error!("Invalid address validation token");
                    continue;
                }

                debug!(
                    "New connection: dcid={} scid={} lcid={}",
                    hex_dump(&hdr.dcid),
                    hex_dump(&hdr.scid),
                    hex_dump(&scid)
                );

                let quic_conn =
                    quiche::accept(&scid, odcid, &mut quiche_config).unwrap();

                connections.insert(scid.to_vec(), (src, (quic_conn, None)));

                connections.get_mut(&scid[..]).unwrap()
            } else {
                connections.get_mut(&hdr.dcid).unwrap()
            };

            // Process potentially coalesced packets.
            let read = match quich3_conn.0.recv(buf) {
                Ok(v) => v,

                Err(quiche::Error::Done) => {
                    debug!("{} done reading", quich3_conn.0.trace_id());
                    break;
                },

                Err(e) => {
                    error!("{} recv failed: {:?}", quich3_conn.0.trace_id(), e);
                    quich3_conn.0.close(false, e.to_wire(), b"fail").unwrap();
                    break 'read;
                },
            };

            debug!("{} processed {} bytes", quich3_conn.0.trace_id(), read);

            if quich3_conn.0.is_established() {
                if b"h3-17" != quich3_conn.0.application_proto() {
                    // TODO a better error code?
                    quich3_conn
                        .0
                        .close(false, 0x0, b"I don't support your ALPNs")
                        .unwrap();
                    break;
                }

                let mut h3_config = quiche::h3::Config::new().unwrap();
                h3_config.set_root_dir(&String::from(args.get_str("--root")));

                if quich3_conn.1.is_none() {
                    let mut h3_conn = quiche::h3::accept(&mut h3_config).unwrap();
                    h3_conn.send_settings(&mut *quich3_conn.0);
                    h3_conn.open_qpack_streams(&mut *quich3_conn.0);

                    // TODO some sanity checking that H3 conn is ok before
                    // adding it to the collection
                    quich3_conn.1 = Some(h3_conn);
                }
            }

            let streams: Vec<u64> = quich3_conn.0.readable().collect();
            for s in streams {
                info!("{} stream id {} is readable", quich3_conn.0.trace_id(), s);
                let mut h3_frames: Vec<quiche::h3::frame::Frame> = Vec::new();
                loop {
                    match quich3_conn
                        .1
                        .as_mut()
                        .unwrap()
                        .handle_stream(&mut *quich3_conn.0, s) {
                            Ok(f) => {
                                h3_frames.push(f);
                            },

                            Err(quiche::h3::Error::Done) => {
                                debug!("{} done handling stream id {}", quich3_conn.0.trace_id(), s);
                                break;
                            },

                            Err(e) => {
                                error!("{} handling stream id {} failed: {:?}", quich3_conn.0.trace_id(), s, e);
                                quich3_conn.0.close(false, e.to_wire(), b"HTTP/3 fail").unwrap();
                                break;
                            },
                        };
                }

                for mut f in h3_frames {
                    match quich3_conn
                        .1
                        .as_mut()
                        .unwrap()
                        .handle_frame(&mut *quich3_conn.0, s, &mut f) {
                        Err(e) => {
                            error!("{} handling frame {:?} on stream id {} failed: {:?}", quich3_conn.0.trace_id(), f, s, e);
                            quich3_conn.0.close(false, e.to_wire(), b"HTTP/3 fail").unwrap();
                            break;
                        },
                        _ => {
                            // TODO
                        }
                    }
                }
            }
        }

        for (peer, quich3_conn) in connections.values_mut() {
            loop {
                let write = match quich3_conn.0.send(&mut out) {
                    Ok(v) => v,

                    Err(quiche::Error::Done) => {
                        debug!("{} done writing", quich3_conn.0.trace_id());
                        break;
                    },

                    Err(e) => {
                        error!(
                            "{} send failed: {:?}",
                            quich3_conn.0.trace_id(),
                            e
                        );
                        quich3_conn.0.close(false, e.to_wire(), b"fail").unwrap();
                        break;
                    },
                };

                // TODO: coalesce packets.
                socket.send_to(&out[..write], &peer).unwrap();

                debug!("{} written {} bytes", quich3_conn.0.trace_id(), write);
            }
        }

        // Garbage collect closed connections.
        connections.retain(|_, (_, ref mut c)| {
            debug!("Collecting garbage");

            if c.0.is_closed() {
                info!(
                    "{} connection collected {:?}",
                    c.0.trace_id(),
                    c.0.stats()
                );
            }

            !c.0.is_closed()
        });
    }
}

fn mint_token(hdr: &quiche::Header, src: &net::SocketAddr) -> Vec<u8> {
    let mut token = Vec::new();

    token.extend_from_slice(b"quiche");

    let addr = match src.ip() {
        std::net::IpAddr::V4(a) => a.octets().to_vec(),
        std::net::IpAddr::V6(a) => a.octets().to_vec(),
    };

    token.extend_from_slice(&addr);
    token.extend_from_slice(&hdr.dcid);

    token
}

fn validate_token<'a>(
    src: &net::SocketAddr, token: &'a [u8],
) -> Option<&'a [u8]> {
    if token.len() < 6 {
        return None;
    }

    if &token[..6] != b"quiche" {
        return None;
    }

    let token = &token[6..];

    let addr = match src.ip() {
        std::net::IpAddr::V4(a) => a.octets().to_vec(),
        std::net::IpAddr::V6(a) => a.octets().to_vec(),
    };

    if token.len() < addr.len() || &token[..addr.len()] != addr.as_slice() {
        return None;
    }

    let token = &token[addr.len()..];

    Some(&token[..])
}

fn hex_dump(buf: &[u8]) -> String {
    let vec: Vec<String> = buf.iter().map(|b| format!("{:02x}", b)).collect();

    vec.join("")
}
