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

use http::Request;
use http::Uri;
use ring::rand::*;

const LOCAL_CONN_ID_LEN: usize = 16;

const MAX_DATAGRAM_SIZE: usize = 1452;

const USAGE: &str = "Usage:
  h3client [options] URL
  h3client -h | --help

Options:
  --wire-version VERSION  The version number to send to the server [default: babababa].
  --no-verify             Don't verify server's certificate.
  -h --help               Show this screen.
";

fn main() {
    let mut buf = [0; 65535];
    let mut out = [0; MAX_DATAGRAM_SIZE];

    env_logger::init();

    let args = docopt::Docopt::new(USAGE)
        .and_then(|dopt| dopt.parse())
        .unwrap_or_else(|e| e.exit());

    let uri = args.get_str("URL").parse::<Uri>().unwrap();
    let uri_authority = uri.authority_part().unwrap().as_str();
    let uri_host = uri.host().unwrap();

    let socket = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
    socket.connect(&uri_authority).unwrap();

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

    let mut scid = [0; LOCAL_CONN_ID_LEN];
    SystemRandom::new().fill(&mut scid[..]).unwrap();

    let version = args.get_str("--wire-version");
    let version = u32::from_str_radix(version, 16).unwrap();

    let mut quiche_config = quiche::Config::new(version).unwrap();

    quiche_config.verify_peer(true);

    quiche_config
        .set_application_protos(&[b"h3-17", b"hq-17"])
        .unwrap();

    quiche_config.set_idle_timeout(30);
    quiche_config.set_max_packet_size(MAX_DATAGRAM_SIZE as u64);
    quiche_config.set_initial_max_data(10_000_000);
    quiche_config.set_initial_max_stream_data_bidi_local(1_000_000);
    quiche_config.set_initial_max_stream_data_bidi_remote(1_000_000);
    quiche_config.set_initial_max_streams_bidi(100);
    quiche_config.set_initial_max_streams_uni(100);
    quiche_config.set_disable_migration(true);

    if args.get_bool("--no-verify") {
        quiche_config.verify_peer(false);
    }

    if std::env::var_os("SSLKEYLOGFILE").is_some() {
        quiche_config.log_keys();
    }

    let mut quic_conn =
        quiche::connect(Some(uri_host), &scid, &mut quiche_config).unwrap();

    let mut h3_config = quiche::h3::Config::new().unwrap();
    let mut h3conn = quiche::h3::connect(&mut h3_config).unwrap();

    let write = match quic_conn.send(&mut out) {
        Ok(v) => v,

        Err(e) => panic!("{} initial send failed: {:?}", quic_conn.trace_id(), e),
    };

    socket.send(&out[..write]).unwrap();

    debug!("{} written {}", quic_conn.trace_id(), write);

    let mut req_sent = false;

    loop {
        poll.poll(&mut events, quic_conn.timeout()).unwrap();

        'read: loop {
            if events.is_empty() {
                debug!("timed out");

                quic_conn.on_timeout();

                break 'read;
            }

            let len = match socket.recv(&mut buf) {
                Ok(v) => v,

                Err(e) => {
                    if e.kind() == std::io::ErrorKind::WouldBlock {
                        debug!("recv() would block");
                        break 'read;
                    }

                    panic!("recv() failed: {:?}", e);
                },
            };

            debug!("{} got {} bytes", quic_conn.trace_id(), len);

            // Process potentially coalesced packets.
            let read = match quic_conn.recv(&mut buf[..len]) {
                Ok(v) => v,

                Err(quiche::Error::Done) => {
                    debug!("{} done reading", quic_conn.trace_id());
                    break;
                },

                Err(e) => {
                    error!("{} recv failed: {:?}", quic_conn.trace_id(), e);
                    quic_conn.close(false, e.to_wire(), b"fail").unwrap();
                    break 'read;
                },
            };

            debug!("{} processed {} bytes", quic_conn.trace_id(), read);
        }

        if quic_conn.is_closed() {
            debug!("{} connection closed", quic_conn.trace_id());
            break;
        }

        if quic_conn.is_established() && !req_sent {
            debug!(
                "{} QUIC handshake completed, now trying HTTP/3",
                quic_conn.trace_id()
            );

            if b"h3-17" != quic_conn.application_proto() {
                // TODO a better error code?
                quic_conn
                    .close(false, 0x0, b"I don't support your ALPNs")
                    .unwrap();
                break;
            }

            // TODO make opening control streams saner
            if !h3conn.is_established() {
                h3conn.send_settings(&mut *quic_conn);
                h3conn.open_qpack_streams(&mut *quic_conn);
            }

            h3conn.create_placeholder_tree(&mut *quic_conn);


            let req = Request::builder()
                .method("GET")
                .uri(&uri)
                .version(http::Version::HTTP_2)
                .header("User-Agent", "quiche-http/3")
                .body(())
                .unwrap();

            info!("Sending HTTP request {:?}", req);

            if let Err(e) = h3conn.send_request(&mut *quic_conn, req, false) {
                error!("{} stream send failed {:?}", quic_conn.trace_id(), e);
            } else {
                req_sent = true;
            }
        }

        let streams: Vec<u64> = quic_conn.readable().collect();
        for s in streams {
            info!("{} stream id {} is readable", quic_conn.trace_id(), s);
            let mut h3_frames: Vec<quiche::h3::frame::Frame> = Vec::new();
            loop {
                match h3conn.handle_stream(&mut *quic_conn, s) {
                    Ok(f) => {
                        h3_frames.push(f);
                    },

                    Err(quiche::h3::Error::Done) => {
                        debug!("{} done handling stream id {}", quic_conn.trace_id(), s);
                        break;
                    },

                    Err(e) => {
                        error!("{} handling stream id {} failed: {:?}", quic_conn.trace_id(), s, e);
                        quic_conn.close(false, e.to_wire(), b"HTTP/3 fail").unwrap();
                        break;
                    },
                };
            }

            for mut f in h3_frames {
                match h3conn.handle_frame(&mut *quic_conn, s, &mut f) {
                    Err(e) => {
                        error!("{} handling frame {:?} on stream id {} failed: {:?}", quic_conn.trace_id(), f, s, e);
                        quic_conn.close(false, e.to_wire(), b"HTTP/3 fail").unwrap();
                        break;
                    },
                    _ => {
                        // TODO
                    }
                }
            }
        }

        loop {
            let write = match quic_conn.send(&mut out) {
                Ok(v) => v,

                Err(quiche::Error::Done) => {
                    debug!("{} done writing", quic_conn.trace_id());
                    break;
                },

                Err(e) => {
                    error!("{} send failed: {:?}", quic_conn.trace_id(), e);
                    quic_conn.close(false, e.to_wire(), b"fail").unwrap();
                    break;
                },
            };

            // TODO: coalesce packets.
            socket.send(&out[..write]).unwrap();

            debug!("{} written {}", quic_conn.trace_id(), write);
        }

        if quic_conn.is_closed() {
            info!(
                "{} connection closed, {:?}",
                quic_conn.trace_id(),
                quic_conn.stats()
            );
            break;
        }
    }
}
