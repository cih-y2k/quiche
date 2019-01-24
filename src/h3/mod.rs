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

//! HTTP/3 client and server.

use crate::octets;

use std::collections::BTreeMap;

use http::{
    Request,
    Response,
    StatusCode,
    Uri,
};

pub type Result<T> = std::result::Result<T, Error>;

/// An HTTP/3 error.
#[derive(Clone, Copy, Debug, PartialEq)]
#[repr(C)]
pub enum Error {
    /// There is no error, just stream or connection close.
    Done                 = -1,

    /// The provided buffer is too short.
    BufferTooShort       = -2,

    /// Setting sent in wrong direction.
    WrongSettingDirection = -3,

    /// The server attempted to push content that the client will not accept.
    PushRefused          = -4,

    /// Internal error in the H3 stack.
    InternalError        = -5,

    /// The server attempted to push something the client already has.
    PushAlreadyInCache   = -6,

    /// The client no longer needs the requested data.
    RequestCancelled     = -7,

    /// The request stream terminated before completing the request.
    IncompleteRequest    = -8,

    /// Forward connection failure for CONNECT target.
    ConnectError         = -9,

    /// Endpoint detected that the peer is exhibiting behaviour that causes.
    /// excessive load
    ExcessiveLoad        = -10,

    /// Operation cannot be served over HTT/3. Retry over HTTP/1.1.
    VersionFallback      = -11,

    /// Frame received on stream where it is not permitted.
    WrongStream          = -12,

    /// Stream ID, Push ID or Placeholder Id greater that current maximum was.
    /// used
    LimitExceeded        = -13,

    /// Push ID used in two different stream headers.
    DuplicatePush        = -14,

    /// Unknown unidirection stream type.
    UnknownStreamType    = -15,

    /// Too many unidirectional streams of a type were created.
    WrongStreamCount     = -16,

    /// A required critical stream was closed.
    ClosedCriticalStream = -17,

    /// Unidirectional stream type opened at peer that is prohibited.
    WrongStreamDirection = -18,

    /// Inform client that remainder of request is not needed. Used in
    /// STOP_SENDING only.
    EarlyResponse        = -19,

    /// No SETTINGS frame at beggining of control stream.
    MissingSettings      = -20,

    /// A frame was received which is not permitted in the current state.
    UnexpectedFrame      = -21,

    /// Server rejected request without performing any application processing.
    RequestRejected      = -22,

    /// Peer violated protocol requirements in a way that doesn't match a more
    /// specific code.
    GeneralProtocolError = -23,

    /// TODO: malformed frame where last on-wire byte is the frame type.
    MalformedFrame       = -24,

    /// QPACK Header block decompression failure.
    QpackDecompressionFailed = -25,

    /// QPACK encoder stream error.
    QpackEncoderStreamError = -26,

    /// QPACK decoder stream error.
    QpackDecoderStreamError = -27,
}

impl Error {
    pub fn to_wire(&self) -> u16 {
        match self {
            Error::Done => 0x0,
            Error::WrongSettingDirection => 0x1,
            Error::PushRefused => 0x2,
            Error::InternalError => 0x3,
            Error::PushAlreadyInCache => 0x4,
            Error::RequestCancelled => 0x5,
            Error::IncompleteRequest => 0x6,
            Error::ConnectError => 0x07,
            Error::ExcessiveLoad => 0x08,
            Error::VersionFallback => 0x09,
            Error::WrongStream => 0xA,
            Error::LimitExceeded => 0xB,
            Error::DuplicatePush => 0xC,
            Error::UnknownStreamType => 0xD,
            Error::WrongStreamCount => 0xE,
            Error::ClosedCriticalStream => 0xF,
            Error::WrongStreamDirection => 0x10,
            Error::EarlyResponse => 0x11,
            Error::MissingSettings => 0x12,
            Error::UnexpectedFrame => 0x13,
            Error::RequestRejected => 0x14,
            Error::GeneralProtocolError => 0xFF,
            Error::MalformedFrame => 0x10,

            Error::QpackDecompressionFailed => 0x20, // TODO: value is TBD
            Error::QpackEncoderStreamError => 0x21, // TODO: value is TBD
            Error::QpackDecoderStreamError => 0x22, // TODO: value is TBD
            Error::BufferTooShort => 0x999,
        }
    }
}

impl std::convert::From<super::Error> for Error {
    fn from(err: super::Error) -> Self {
        match err {
            super::Error::Done => Error::Done,
            super::Error::BufferTooShort => Error::BufferTooShort,
            _ => Error::GeneralProtocolError,
        }
    }
}

fn req_hdrs_to_qpack(
    encoder: &mut qpack::Encoder, request: &http::Request<()>,
) -> Vec<u8> {
    let mut vec = vec![0u8; 65535];

    let mut headers: Vec<qpack::Header> = Vec::new();

    headers.push(qpack::Header::new(":method", request.method().as_str()));
    headers.push(qpack::Header::new(
        ":scheme",
        request.uri().scheme_str().unwrap(),
    ));
    headers.push(qpack::Header::new(
        ":authority",
        request.uri().host().unwrap(),
    ));
    headers.push(qpack::Header::new(
        ":path",
        request.uri().path_and_query().unwrap().as_str(),
    ));

    for (key, value) in request.headers().iter() {
        headers.push(qpack::Header::new(key.as_str(), value.to_str().unwrap()));
    }

    let len = encoder.encode(&headers, &mut vec);

    vec.truncate(len.unwrap());
    trace!("Encoded header block len={:?}", len);

    vec
}

fn resp_hdrs_to_qpack(
    encoder: &mut qpack::Encoder, response: &http::Response<()>,
) -> Vec<u8> {
    let mut vec = vec![0u8; 65535];

    let mut headers: Vec<qpack::Header> = Vec::new();

    headers.push(qpack::Header::new(":status", response.status().as_str()));

    for (key, value) in response.headers().iter() {
        headers.push(qpack::Header::new(key.as_str(), value.to_str().unwrap()));
    }

    let len = encoder.encode(&headers, &mut vec);

    vec.truncate(len.unwrap());
    trace!("Encoded header block len={:?}", len);

    vec
}

fn req_hdrs_from_qpack(
    decoder: &mut qpack::Decoder, hdr_block: &mut [u8],
) -> http::Request<()> {
    let mut req: Request<()> = Request::default();

    // TODO: make pseudo header parsing more efficient. Right now, we create
    // some variables to hold pseudo headers that may arrive in any order.
    // Some of these are later formatted back into a complete URI
    let mut method = String::new();
    let mut scheme = String::new();
    let mut authority = String::new();
    let mut path = String::new();

    for hdr in decoder.decode(hdr_block).unwrap() {
        // trace!("Header field - {}:{}", hdr.0, hdr.1);

        match hdr.name() {
            ":method" => {
                method = hdr.value().to_string();
            },
            ":scheme" => {
                scheme = hdr.value().to_string();
            },
            ":authority" => {
                authority = hdr.value().to_string();
            },
            ":path" => {
                path = hdr.value().to_string();
            },
            _ => {
                req.headers_mut().insert(
                    http::header::HeaderName::from_bytes(hdr.name().as_bytes())
                        .unwrap(),
                    http::header::HeaderValue::from_str(hdr.value()).unwrap(),
                );
            },
        }
    }

    let uri = format!("{}://{}{}", scheme, authority, path);

    *req.method_mut() = method.parse().unwrap();
    *req.version_mut() = http::Version::HTTP_2;
    *req.uri_mut() = uri.parse::<Uri>().unwrap();

    // debug!("Prepared request {:?}", req);

    req
}

fn resp_hdrs_from_qpack(
    decoder: &mut qpack::Decoder, hdr_block: &mut [u8],
) -> http::Response<()> {
    let mut resp: Response<()> = Response::default();

    // TODO: make pseudo header parsing more efficient.
    let mut status = String::new();

    for hdr in decoder.decode(hdr_block).unwrap() {
        // trace!("Header field - {}:{}", hdr.0, hdr.1);

        match hdr.name() {
            ":status" => {
                status = hdr.value().to_string();
            },
            _ => {
                resp.headers_mut().insert(
                    http::header::HeaderName::from_bytes(hdr.name().as_bytes())
                        .unwrap(),
                    http::header::HeaderValue::from_str(hdr.value()).unwrap(),
                );
            },
        }
    }

    *resp.status_mut() = StatusCode::from_bytes(status.as_bytes()).unwrap();
    *resp.version_mut() = http::Version::HTTP_2;

    // debug!("Prepared response {:?}", resp);

    resp
}

/// An HTTP/3 configuration.
pub struct Config {
    pub root_dir: String,
    pub num_placeholders: u64,
    pub max_header_list_size: u64,
    pub qpack_max_table_capacity: u64,
    pub qpack_blocked_streams: u64,
}

impl Config {
    #[allow(clippy::new_ret_no_self)]
    pub fn new() -> Result<Config> {
        Ok(Config {
            root_dir: String::new(),
            num_placeholders: 16,
            max_header_list_size: 0,
            qpack_max_table_capacity: 0,
            qpack_blocked_streams: 0,
        })
    }

    pub fn set_root_dir(&mut self, root_dir: &String) {
        self.root_dir = String::clone(root_dir);
    }

    pub fn set_num_placeholders(&mut self, num_placeholders: u64) {
        self.num_placeholders = num_placeholders;
    }

    pub fn set_max_header_list_size(&mut self, max_header_list_size: u64) {
        self.max_header_list_size = max_header_list_size;
    }

    pub fn set_qpack_max_table_capacity(
        &mut self, qpack_max_table_capacity: u64,
    ) {
        self.qpack_max_table_capacity = qpack_max_table_capacity;
    }

    pub fn set_qpacked_blocked_streams(&mut self, qpack_blocked_streams: u64) {
        self.qpack_blocked_streams = qpack_blocked_streams;
    }
}

type RequestMap = BTreeMap<u64, http::Request<()>>;
type StreamMap = BTreeMap<u64, stream::Stream>;

/// An HTTP/3 connection.
pub struct Connection {
    root_dir: String,
    is_server: bool,

    requests: RequestMap,
    streams: StreamMap,
    uni_stream_ledger: Vec<u64>,

    num_placeholders: u64,
    max_header_list_size: u64,
    qpack_max_table_capacity: u64,
    qpack_blocked_streams: u64,

    peer_num_placeholders: Option<u64>,
    peer_max_header_list_size: Option<u64>,
    peer_qpack_max_table_capacity: Option<u64>,
    peer_qpack_blocked_streams: Option<u64>,

    control_stream_id: Option<u64>,
    peer_control_stream_open: bool,

    qpack_encoder: qpack::Encoder,
    qpack_decoder: qpack::Decoder,

    qpack_encoder_stream_open: bool,
    peer_qpack_encoder_stream_open: bool,
    qpack_decoder_stream_open: bool,
    peer_qpack_decoder_stream_open: bool,
}

impl Connection {
    #[allow(clippy::new_ret_no_self)]
    fn new(config: &mut Config, is_server: bool) -> Result<Connection> {
        let root = String::clone(&config.root_dir); // TODO shouldn't need to clone here

        Ok(Connection {
            root_dir: root,
            is_server,
            requests: RequestMap::new(),
            streams: StreamMap::new(),
            uni_stream_ledger: Vec::new(),

            num_placeholders: config.num_placeholders,
            max_header_list_size: config.max_header_list_size,
            qpack_max_table_capacity: config.qpack_max_table_capacity,
            qpack_blocked_streams: config.qpack_blocked_streams,

            peer_num_placeholders: None,
            peer_max_header_list_size: None,
            peer_qpack_max_table_capacity: None,
            peer_qpack_blocked_streams: None,

            control_stream_id: None,
            peer_control_stream_open: false,

            qpack_encoder: qpack::Encoder::new(),
            qpack_decoder: qpack::Decoder::new(),

            qpack_encoder_stream_open: false,
            peer_qpack_encoder_stream_open: false,
            qpack_decoder_stream_open: false,
            peer_qpack_decoder_stream_open: false,
        })
    }

    /// Get a request stream ID if there is one available
    pub fn get_available_request_stream(&mut self, req: http::Request<()>) -> Result<u64> {
        if self.requests.is_empty() {
            self.requests.insert(0, req);
            Ok(0)
        } else {
            let id = self.streams.keys().last().unwrap();

            // TODO: this should check the value of the connection MAX_STREAM_ID
            if id < &std::u64::MAX {
                let id = id + 4;
                Ok(id)
            } else {
                Err(Error::LimitExceeded)
            }
        }
    }

    /// Returns an available stream ID for the local endpoint to use
    fn get_available_uni_stream(&mut self) -> Result<u64> {
        if self.uni_stream_ledger.is_empty() {
            if self.is_server {
                self.uni_stream_ledger.push(0x3);
            } else {
                self.uni_stream_ledger.push(0x2);
            }

            Ok(*self.uni_stream_ledger.last().unwrap())
        } else {
            let id = self.uni_stream_ledger.last().unwrap();

            // TODO: this should check the value of the connection MAX_STREAM_ID
            if id < &std::u64::MAX {
                let id = id + 4;
                Ok(id)
            } else {
                Err(Error::LimitExceeded)
            }
        }
    }

    pub fn is_established(&self) -> bool {
        self.control_stream_id.is_some() &&
            self.qpack_encoder_stream_open &&
            self.qpack_decoder_stream_open
    }

    pub fn open_control_stream(&mut self, quic_conn: &mut super::Connection) -> Result<()> {
        if self.control_stream_id.is_none() {
            let stream_id = self.get_available_uni_stream()?;
            quic_conn
                .stream_send(
                    stream_id,
                    &stream::HTTP3_CONTROL_STREAM_TYPE_ID.to_be_bytes(),
                    false,
                )?;

            self.control_stream_id = Some(stream_id);

        }

        Ok(())
    }

    pub fn open_qpack_streams(&mut self, quic_conn: &mut super::Connection) -> Result<()>{
        if !self.qpack_encoder_stream_open {
            quic_conn
                .stream_send(
                    self.get_available_uni_stream()?,
                    &stream::QPACK_ENCODER_STREAM_TYPE_ID.to_be_bytes(),
                    false,
                )?;

            // TODO await ACK of stream open?
            self.qpack_encoder_stream_open = true;
        }

        if !self.qpack_decoder_stream_open {
            quic_conn
                .stream_send(
                    self.get_available_uni_stream()?,
                    &stream::QPACK_DECODER_STREAM_TYPE_ID.to_be_bytes(),
                    false,
                )?;

            // TODO await ACK of stream open?
            self.qpack_decoder_stream_open = true;
        }

        Ok(())
    }

    pub fn create_placeholder_tree(&mut self, quic_conn: &mut super::Connection) -> Result<()>{
        if self.is_server {
            error!("Server cannot send prioritisation information!");
            return Err(Error::GeneralProtocolError);
        }

        if self.num_placeholders > 0 {
            debug!("Going to prioritise {} placeholders", self.num_placeholders);
            // TODO make sure slice is large enough to hold
            // *all* PRIORITY frames. Worst case is ~7 bytes per frame.
            let mut d = [42; 255];
            let mut b = octets::Octets::with_slice(&mut d);

            let mut weight = 0;
            for i in 0..self.num_placeholders {
                let frame = frame::Frame::Priority {
                    priority_elem: frame::PrioritizedElemType::Placeholder,
                    elem_dependency: frame::ElemDependencyType::RootOfTree,
                    prioritized_element_id: Some(i),
                    element_dependency_id: None,
                    weight,
                };

                frame.to_bytes(&mut b)?;

                weight += 1;
            }

            let off = b.off();
            debug!("Amount of priority bytes to send is {}", off);

            match self.control_stream_id {
                Some(id) => {
                    quic_conn.stream_send(id, &d[..off], false)?;
                },
                None => {
                    return Err(Error::InternalError);
                }
            }
        }

        Ok(())
    }

    /// Send SETTINGS frame based on HTTP/3 config.
    pub fn send_settings(&mut self, quic_conn: &mut super::Connection) -> Result<()>{
        self.open_control_stream(quic_conn)?;

        let mut d = [42; 128];

        let num_placeholders = if self.is_server { Some(16) } else { None };

        let frame = frame::Frame::Settings {
            num_placeholders,
            max_header_list_size: Some(1024),
            qpack_max_table_capacity: None,
            qpack_blocked_streams: None,
        };

        let mut b = octets::Octets::with_slice(&mut d);

        let frame_size = frame.to_bytes(&mut b).unwrap();
        let off = b.off();
        trace!("Frame size is {} and octet offset is {}", frame_size, off);

        debug!("Control stream id will be {:?}!", self.control_stream_id);
        match self.control_stream_id {

            Some(id) => {
                quic_conn.stream_send(id, &d[..off], false)?;
            },
            None => {
                return Err(Error::InternalError);
            }
        }

        Ok(())
    }

    /// Prepare a request in HTTP/3 wire format, allocate a stream ID and send
    /// it.
    pub fn send_request(
        &mut self, quic_conn: &mut super::Connection, request: http::Request<()>,
        has_body: bool,
    ) -> Result<()>{
        let mut d = [42; 65535];

        let req_frame = frame::Frame::Headers {
            header_block: req_hdrs_to_qpack(&mut self.qpack_encoder, &request),
        };

        let mut b = octets::Octets::with_slice(&mut d);
        req_frame.to_bytes(&mut b).unwrap();

        let stream_id = self.get_available_request_stream(request)?;
        self.streams.insert(stream_id, stream::Stream::new(stream_id, true)?);

        let off = b.off();

        trace!(
            "{} sending request of size {} on stream {}",
            quic_conn.trace_id(),
            off,
            stream_id
        );

        if let Err(e) = quic_conn.stream_send(stream_id, &d[..off], !has_body) {
            error!("{} stream send failed {:?}", quic_conn.trace_id(), e);
            return Err(Error::from(e))
        }

        Ok(())
    }

    /// Send a response.
    pub fn send_response(
        &mut self, quic_conn: &mut super::Connection, stream_id: u64,
        response: http::Response<()>, has_body: bool,
    ) {
        let mut d = [42; 65535];

        let headers = frame::Frame::Headers {
            header_block: resp_hdrs_to_qpack(&mut self.qpack_encoder, &response),
        };

        let mut b = octets::Octets::with_slice(&mut d);
        headers.to_bytes(&mut b).unwrap();

        // TODO figure out type management of Response object
        // theory is that if there is no type, there can be no body
        // if !response.body().is_empty() {
        // let data = frame::Frame::Data {
        // payload: response.body().as_bytes().to_vec()
        // };
        // data.to_bytes(&mut b).unwrap();
        // }

        let off = b.off();

        trace!(
            "{} sending response of size {} on stream {}",
            quic_conn.trace_id(),
            off,
            stream_id
        );

        if let Err(e) = quic_conn.stream_send(stream_id, &d[..off], !has_body) {
            error!("{} stream send failed {:?}", quic_conn.trace_id(), e);
        }
    }

    fn _unique_stream_type_already_exist(
        &self, stream_id: u64, ty: stream::StreamType,
    ) -> bool {
        for (id, s) in self.streams.iter() {
            if *id != stream_id && s.get_stream_type().clone().unwrap() == ty {
                return true;
            }
        }

        false
    }

    pub fn handle_frame(
        &mut self, quic_conn: &mut super::Connection, stream_id: u64,
        frame: &mut frame::Frame,
    ) -> Result<()> {
        match frame {
            frame::Frame::Settings {
                num_placeholders,
                max_header_list_size,
                qpack_max_table_capacity,
                qpack_blocked_streams,
            } =>
                if self.is_server && num_placeholders.is_some() {
                    error!("SETTINGS frame with placeholders received at server");
                    return Err(Error::WrongSettingDirection);
                } else {
                    debug!("Settings frame processed.");
                    self.peer_num_placeholders = *num_placeholders;
                    self.peer_max_header_list_size = *max_header_list_size;
                    self.peer_qpack_max_table_capacity =
                        *qpack_max_table_capacity;
                    self.peer_qpack_blocked_streams = *qpack_blocked_streams;
                    self.peer_control_stream_open = true;
                },
            frame::Frame::Priority { .. } => {
                debug!("PRIORITY frame received but not doing anything.");
            },
            frame::Frame::CancelPush { .. } => {
                debug!("CANCEL_PUSH frame received but not doing anything.");
            },
            frame::Frame::MaxPushId { .. } => {
                debug!("MAX_PUSH_ID frame received but not doing anything.");
            },
            frame::Frame::GoAway { .. } =>
                if self.is_server {
                    error!("GOAWAY frame received at server.");
                    return Err(Error::UnexpectedFrame);
                } else {
                    debug!("GOAWAY frame received but not doing anything.");
                },
            frame::Frame::Headers { header_block } => {
                // TODO: allow logic to happen outside the library
                if self.is_server {
                    let req =
                        self.parse_request_header_block(&mut header_block[..]);

                    info!("got request {:?} on stream ID {}", req, stream_id,);

                    // TODO *actually* parse the request and let some other part
                    // of the code respond with something
                    // other than 404
                    let resp = Response::builder()
                        .status(404)
                        .version(http::Version::HTTP_2)
                        .header("Server", "quiche-http/3")
                        .body(())
                        .unwrap();

                    // TODO: logic like this is does not belong here
                    self.send_response(quic_conn, stream_id, resp, false);
                } else {
                    let resp =
                        self.parse_response_header_block(&mut header_block[..]);
                    info!("got response {:?}", resp,);

                    info!(
                        "{} response received, closing..,",
                        quic_conn.trace_id()
                    );

                    // TODO: logic like this is does not belong here
                    quic_conn.close(true, 0x00, b"kthxbye").unwrap();
                }
            },
            _ => {
                // TODO: we should ignore unknown frame types but for now
                // generate an error and let someone else deal with it.
                debug!("Unknown frame type received.");
                return Err(Error::UnexpectedFrame);
            },
        }

        Ok(())
    }

    fn parse_request_header_block(
        &mut self, hdr_block: &mut [u8],
    ) -> http::Request<()> {
        // dbg!(hdr_block);

        req_hdrs_from_qpack(&mut self.qpack_decoder, hdr_block)
    }

    fn parse_response_header_block(
        &mut self, hdr_block: &mut [u8],
    ) -> http::Response<()> {
        // dbg!(hdr_block);
        resp_hdrs_from_qpack(&mut self.qpack_decoder, hdr_block)
    }

    pub fn handle_stream(
        &mut self, quic_conn: &mut super::Connection, stream_id: u64,
    ) -> Result<(frame::Frame)> {
        let stream = self
            .streams
            .entry(stream_id)
            .or_insert(stream::Stream::new(stream_id, false)?);

        info!(
            "Stream id {} is of type {:?}",
            stream_id,
            stream.get_stream_type()
        );
        trace!(
            "Stream id {} is in {:?} state",
            stream_id,
            stream.get_stream_state()
        );
        let mut d = vec![0; 124];
        let (read, _fin) = quic_conn.stream_recv(stream_id, &mut d)?;
        //dbg!(&d);
        debug!("{} received {} bytes on stream {}", quic_conn.trace_id(), read, stream_id);
        stream.add_data(&mut d.drain(..read).collect())?;

        while stream.more() {
            match stream.get_stream_state() {
                stream::StreamState::StreamTypeLen => {
                    // stream.add_data(&mut d.drain(..read).collect())?;

                    // TODO: draft 18 uses 1 byte stream type, so we can double
                    // jump through states
                    let varint_len = 1;
                    // draft 18+ let varint_len =
                    // octets::Octets::varint_parse_len(stream.buf[stream.
                    // buf_read_off])?;
                    stream.set_stream_type_len(varint_len)?;

                    // draft 18+ we don't set the type here, all the following
                    // code should be moved to the next state match
                    // `StreamTypeLen` and checked to make sure it is valid for
                    // true varints
                    let varint_bytes =
                        stream.buf_bytes(varint_len as usize)?;
                    let varint = varint_bytes[0];

                    let ty = stream::StreamType::deserialize(varint);

                    if ty.is_none() {
                        return Err(Error::UnknownStreamType);
                    } else {
                        info!("Stream id {} is of type {:?}", stream_id, ty.unwrap());
                    }

                    // TODO: consider if we want to set type later, after
                    // validation...
                    stream.set_stream_type(ty)?;

                    match &ty {
                        Some(stream::StreamType::Control) => {
                            // only one control stream allowed.
                            // if self.unique_stream_type_already_exist(stream_id,
                            // stream::StreamType::Control) {
                            if self.peer_control_stream_open {
                                error!("Peer already opened a control stream!");
                                return Err(Error::WrongStreamCount);
                            } else {
                                self.peer_control_stream_open = true;
                            }
                            //}
                        },
                        Some(stream::StreamType::Push) => {
                            // only clients can receive push stream.
                            if self.is_server {
                                error!("Client opened a push stream!");
                                return Err(Error::WrongStreamDirection);
                            }
                        },
                        Some(stream::StreamType::QpackEncoder) => {
                            // only one qpack encoder stream allowed.
                            // if self.unique_stream_type_already_exist(stream_id,
                            // stream::StreamType::QpackEncoder) {
                            if self.peer_qpack_encoder_stream_open {
                                error!(
                                    "Peer already opened a QPACK encoder stream!"
                                );
                                return Err(Error::WrongStreamCount);
                            } else {
                                self.peer_qpack_encoder_stream_open = true;
                            }
                        },
                        Some(stream::StreamType::QpackDecoder) => {
                            // only one qpack decoder allowed.
                            // if self.unique_stream_type_already_exist(stream_id,
                            // stream::StreamType::QpackDecoder) {
                            if self.peer_qpack_decoder_stream_open {
                                error!(
                                    "Peer already opened a QPACK decoder stream!"
                                );
                                return Err(Error::WrongStreamCount);
                            } else {
                                self.peer_qpack_decoder_stream_open = true;
                            }
                        },
                        // TODO: enable GREASE streams
                        /*Some(stream::StreamType::Grease) => {
                            // TODO: Grease stream types should be ignored (by
                            // default). Until then, return an error and let
                            // someone else deal with it. Endpoint should
                            // probably avoid reading from the stream at all?
                            error!("Peer opened a GREASE stream type!");
                            return Err(Error::UnknownStreamType);
                        },*/
                        Some(stream::StreamType::Request) => unreachable!(),
                        None => {
                            // We don't know the type, so we should just ignore
                            // things being sent on this stream. But for now,
                            // return an error and let someone else deal with it.
                            error!("Peer opened an unknown stream type!");
                            return Err(Error::UnknownStreamType);
                        },
                    }
                },
                stream::StreamState::StreamType => {
                    // TODO: populate this in draft 18+
                },
                stream::StreamState::FramePayloadLenLen => {
                    let varint_byte = stream.buf_bytes(1)?[0];
                    trace!(
                        "Frame payload-length length is {} byte(s)",
                        octets::varint_parse_len(varint_byte)
                    );
                    stream.set_next_varint_len(octets::varint_parse_len(
                        varint_byte,
                    ))?
                },
                stream::StreamState::FramePayloadLen => {
                    let varint = stream.get_varint()?;
                    // trace!("Frame payload length is {} byte(s)", varint);
                    stream.set_frame_payload_len(varint)?;
                },
                stream::StreamState::FrameTypeLen => {
                    let varint_byte = stream.buf_bytes(1)?[0];
                    stream.set_next_varint_len(octets::varint_parse_len(
                        varint_byte,
                    ))?
                },
                stream::StreamState::FrameType => {
                    // TODO: draft 18+
                    // let varint = stream.get_varint()?;
                    let varint = stream.get_u8()?;
                    stream.set_frame_type(varint)?;
                },
                stream::StreamState::FramePayload => {
                    return Ok(stream.parse_frame()?);
                },
                _ => {
                    // TODO
                },
            }
        }

        //Ok(())
        Err(Error::Done)
    }


}

/// Creates a new client-side connection.
pub fn connect(config: &mut Config) -> Result<Connection> {
    let conn = Connection::new(config, false)?;

    Ok(conn)
}

/// Creates a new server-side connection.
pub fn accept(config: &mut Config) -> Result<Connection> {
    let conn = Connection::new(config, true)?;

    Ok(conn)
}

pub mod frame;
pub mod qpack;
mod stream;
