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

use super::frame::Frame;
use super::Error;
use super::Result;

use crate::octets;

pub const HTTP3_CONTROL_STREAM_TYPE_ID: u8 = 0x43;
pub const HTTP3_PUSH_STREAM_TYPE_ID: u8 = 0x50;
pub const QPACK_ENCODER_STREAM_TYPE_ID: u8 = 0x48;
pub const QPACK_DECODER_STREAM_TYPE_ID: u8 = 0x68;

#[derive(Clone, Copy, PartialEq)]
pub enum StreamType {
    Control,
    Request,
    Push,
    QpackEncoder,
    QpackDecoder,
    // Grease, // TODO: enable GREASE streams
}

#[derive(Clone, Copy, PartialEq)]
pub enum StreamState {
    StreamTypeLen,
    StreamType,
    FrameTypeLen,
    FrameType,
    FramePayloadLenLen,
    FramePayloadLen,
    FramePayload,
    PushIdLen,
    PushId,
    QpackInstruction,
    Invalid,
    Done,
}

impl std::fmt::Debug for StreamState {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            StreamState::StreamTypeLen => {
                write!(f, "StreamTypeLen")?;
            },
            StreamState::StreamType => {
                write!(f, "StreamType")?;
            },
            StreamState::FrameTypeLen => {
                write!(f, "FrameTypeLen")?;
            },
            StreamState::FrameType => {
                write!(f, "FrameType")?;
            },
            StreamState::FramePayloadLenLen => {
                write!(f, "FramePayloadLenLen")?;
            },
            StreamState::FramePayloadLen => {
                write!(f, "FramePayloadLen")?;
            },
            StreamState::FramePayload => {
                write!(f, "FramePayload")?;
            },
            StreamState::PushIdLen => {
                write!(f, "PushIdLen")?;
            },
            StreamState::PushId => {
                write!(f, "PushId")?;
            },
            StreamState::QpackInstruction => {
                write!(f, "QpackInstruction")?;
            },
            StreamState::Invalid => {
                write!(f, "Invalid")?;
            },
            StreamState::Done => {
                write!(f, "Done")?;
            },
        }

        Ok(())
    }
}

impl StreamType {
    // TODO: draft 18+ with require true varints
    pub fn deserialize(v: u8) -> Option<StreamType> {

        match v {
            HTTP3_CONTROL_STREAM_TYPE_ID => Some(StreamType::Control),
            HTTP3_PUSH_STREAM_TYPE_ID => Some(StreamType::Push),
            QPACK_ENCODER_STREAM_TYPE_ID => Some(StreamType::QpackEncoder),
            QPACK_DECODER_STREAM_TYPE_ID => Some(StreamType::QpackDecoder),
            // TODO: parse grease stream
            _ => {
                trace!("Stream type value {:x} is unknown", v);
                return None;
            }
        }
    }

    // TODO: draft 18+ with require true varints
    pub fn _serialize(ty: StreamType) -> Option<u8> {
        match ty {
            StreamType::Control => Some(HTTP3_CONTROL_STREAM_TYPE_ID),
            StreamType::Push => Some(HTTP3_PUSH_STREAM_TYPE_ID),
            StreamType::QpackEncoder => Some(QPACK_ENCODER_STREAM_TYPE_ID),
            StreamType::QpackDecoder => Some(QPACK_DECODER_STREAM_TYPE_ID),
            _ => None,
        }
    }
}

impl std::fmt::Debug for StreamType {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            StreamType::Control => {
                write!(f, "Control stream")?;
            },
            StreamType::Request => {
                write!(f, "Request stream")?;
            },
            StreamType::Push => {
                write!(f, "Push stream")?;
            },
            StreamType::QpackEncoder => {
                write!(f, "QPACK encoder stream")?;
            },
            StreamType::QpackDecoder => {
                write!(f, "QPACK decoder stream")?;
            },
            // TODO: enable GREASE streams
            /*StreamType::Grease => {
                write!(f, "Grease stream")?;
            },*/
        }

        Ok(())
    }
}

/// An HTTP/3 Stream
pub struct Stream {
    id: u64,
    ty: Option<StreamType>,
    _is_local: bool,
    initialised: bool,
    ty_len: u8,
    state: StreamState,
    stream_offset: u64,
    buf: Vec<u8>,
    buf_read_off: u64,
    buf_end_pos: u64,
    next_varint_len: usize,
    frame_payload_len: u64,
    frame_type: Option<u8>,
}

impl Stream {
    #[allow(clippy::new_ret_no_self)]
    pub fn new(id: u64, is_local: bool) -> Result<Stream> {
        let mut ty = None;
        let mut initialised = false;
        let mut state = StreamState::StreamTypeLen;

        if crate::stream::is_bidi(id) {
            ty = Some(StreamType::Request);
            initialised = true;
            // TODO draft 18+ will mean first state is not FramePayloadLenLen
            state = StreamState::FramePayloadLenLen;
        };

        trace!("Stream id {} is new and is starting in {:?} state", id, state);

        Ok(Stream {
            id,
            ty,
            _is_local: is_local,
            initialised,
            ty_len: 0,
            state,
            stream_offset: 0,
            buf: Vec::new(), /* TODO: need a more elegant
                              * approach to buffer management */
            buf_read_off: 0,
            buf_end_pos: 0,
            next_varint_len: 0,
            frame_payload_len: 0,
            frame_type: None,
        })
    }

    pub fn get_stream_type(&self) -> &Option<StreamType> {
        &self.ty
    }

    pub fn get_stream_state(&mut self) -> &StreamState {
        &self.state
    }

    pub fn _type_len(&self) -> u8 {
        self.ty_len
    }

    // pub fn buf(&mut self) -> &mut [u8] {
    // return &mut self.buf[self.buf_read_off as usize .. self.buf_end_pos as
    // usize]; }

    pub fn buf_bytes(&mut self, size: usize) -> Result<&mut [u8]> {
        // dbg!(&self.buf);
        // check there are enough meaningful bytes to read

        let desired_end_index = self.buf_read_off as usize + size;
        if desired_end_index < self.buf_end_pos as usize + 1 {
            return Ok(
                &mut self.buf[self.buf_read_off as usize..desired_end_index]
            );
        }

        error!("Tried to read {} bytes but we don't have that many.", size);
        Err(Error::BufferTooShort)
    }

    // TODO: this function needs improvement (e.g. avoid copies)
    pub fn add_data(&mut self, d: &mut Vec<u8>) -> Result<()> {
        // TODO: use of unstable library feature 'try_reserve': new API (see issue
        // #48043) self.buf.try_reserve(d.len())?;
        trace!("Stream id {}: adding {} bytes of data buffer", self.id, d.len());
        self.buf_end_pos += d.len() as u64;
        self.buf.append(d);

        //trace!("end_pos is now {}", self.buf_end_pos);

        Ok(())
    }

    // pub fn buf_read_off(&mut self) -> u64 {
    // return self.buf_read_off;
    // }

    pub fn set_stream_type_len(&mut self, len: u8) -> Result<()> {
        if self.state == StreamState::StreamTypeLen {
            self.ty_len = len;
            self.do_state_transition(StreamState::StreamType);
            return Ok(());
        }

        Err(Error::InternalError)
    }

    pub fn set_stream_type(&mut self, ty: Option<StreamType>) -> Result<()> {
        if self.state == StreamState::StreamType {
            self.ty = ty.clone();
            self.stream_offset += u64::from(self.ty_len);
            self.buf_read_off += u64::from(self.ty_len);

            match ty {
                Some(StreamType::Request) => {
                    // TODO: draft18+ will not start in FramePayloadLenLen
                    self.do_state_transition(StreamState::FramePayloadLenLen);
                },
                Some(StreamType::Control) => {
                    // TODO: draft18+ will not start in FramePayloadLenLen
                    self.do_state_transition(StreamState::FramePayloadLenLen);
                },
                Some(StreamType::Push) => {
                    self.do_state_transition(StreamState::PushIdLen);
                },
                Some(StreamType::QpackEncoder) |
                Some(StreamType::QpackDecoder) => {
                    self.do_state_transition(StreamState::QpackInstruction);
                    self.initialised = true;
                },
                // TODO: enable GREASE streams
                /*
                Some(StreamType::Grease) => {
                    self.state = StreamState::Done;
                },*/
                None => {
                    self.do_state_transition(StreamState::Invalid);
                },
            };

            return Ok(());
        }

        Err(Error::InternalError)
    }

    pub fn set_next_varint_len(&mut self, len: usize) -> Result<()> {
        trace!("Next varint length is {} bytes", len);
        self.next_varint_len = len;

        match self.state {
            StreamState::FramePayloadLenLen =>
                self.do_state_transition(StreamState::FramePayloadLen),
            StreamState::FrameTypeLen => self.do_state_transition(StreamState::FrameType),
            StreamState::PushIdLen => self.do_state_transition(StreamState::PushId),
            _ => { /*TODO*/ },
        }

        Ok(())
    }

    pub fn get_varint(&mut self) -> Result<(u64)> {
        if self.buf.len() - self.buf_read_off as usize >=
            self.next_varint_len as usize
        {
            let n = self.buf_read_off as usize + self.next_varint_len;
            let varint = octets::Octets::with_slice(
                &mut self.buf[self.buf_read_off as usize..n],
            )
            .get_varint()?;
            trace!("Varint value is {}", varint);
            self.stream_offset += self.next_varint_len as u64;
            self.buf_read_off += self.next_varint_len as u64;

            return Ok(varint);
        }

        Err(Error::Done)
    }

    // TODO: we probably don't need this in draft 18+
    pub fn get_u8(&mut self) -> Result<(u8)> {
        let ret = self.buf_bytes(1)?[0];

        self.stream_offset += 1;
        self.buf_read_off += 1;

        Ok(ret)
    }

    pub fn _set_push_id(&mut self, _id: u64) -> Result<()> {
        // Only push streams expect to have a push ID
        if self.ty == Some(StreamType::Push) {
            // TODO: do something useful
            self.initialised = true;
            trace!("Stream {} is now initialised.", self.id);
        } else {
            return Err(Error::InternalError);
        }

        Ok(())
    }

    pub fn set_frame_payload_len(&mut self, len: u64) -> Result<()> {
        // Only expect frames on Control, Request and Push streams
        if self.ty == Some(StreamType::Control) ||
            self.ty == Some(StreamType::Request) ||
            self.ty == Some(StreamType::Push)
        {
            self.frame_payload_len = len;
            self.do_state_transition(StreamState::FrameTypeLen);

            return Ok(());
        }

        Err(Error::UnexpectedFrame)
    }

    pub fn _get_frame_payload_len(&self) -> u64 {
        return self.frame_payload_len;
    }

    fn do_state_transition(&mut self, s: StreamState) {
        self.state = s;

        trace!(
            "Stream {} transitioned to {:?} state",
            self.id,
            self.state
        );
    }

    pub fn set_frame_type(&mut self, ty: u8) -> Result<()> {
        // Only expect frames on Control, Request and Push streams
        trace!("Frame type val is {}", ty);

        match self.ty {
            Some(StreamType::Control) => {
                trace!("a");
                // Control stream starts uninitialised and only SETTINGS is
                // accepted in that state. Other frames cause an
                // error. Once initialised, no more SETTINGS are
                // permitted.
                if !self.initialised {
                    trace!("b");
                    match ty {
                        super::frame::SETTINGS_FRAME_TYPE_ID => {
                            self.frame_type = Some(ty);
                            self.do_state_transition(StreamState::FramePayload);

                            self.initialised = true;
                        },
                        _ => {
                            trace!("Stream {} not intialised and attempt to process a {:?} was made, this is an error.", self.id, ty);
                            return Err(Error::MissingSettings);
                        },
                    }
                } else {
                    trace!("c");
                    match ty {
                        super::frame::SETTINGS_FRAME_TYPE_ID => {
                            trace!("Stream {} was intialised and attempt to process  {:?} was made, this is an error.", self.id, ty);
                            return Err(Error::UnexpectedFrame);
                        },
                        _ => {
                            self.frame_type = Some(ty);
                            self.do_state_transition(StreamState::FramePayload);
                        },
                    }
                }
            },
            Some(StreamType::Request) => {
                trace!("l");
                match ty {
                    super::frame::HEADERS_FRAME_TYPE_ID  |
                     super::frame::DATA_FRAME_TYPE_ID |
                     super::frame::PRIORITY_FRAME_TYPE_ID |
                     super::frame::PUSH_PROMISE_FRAME_TYPE_ID => {
                        self.frame_type = Some(ty);
                        self.do_state_transition(StreamState::FramePayload);
                    },
                    _ => {
                        error!("Unexpected frame type {} on request stream {}", ty, self.id);
                        return Err(Error::UnexpectedFrame);
                    }
                }
                self.frame_type = Some(ty);

            }
            Some(StreamType::Push) => {
                trace!("x");
                self.frame_type = Some(ty);
                // TODO: draft18+
                self.do_state_transition(StreamState::FramePayloadLenLen);
            },
            _ => {
                error!("Unexpected frame type {} on stream {}", ty, self.id);
                return Err(Error::UnexpectedFrame);
            },
        }

        Ok(())
    }

    pub fn _get_frame_type(&self) -> u8 {
        self.frame_type.unwrap()
    }

    pub fn parse_frame(&mut self) -> Result<(super::frame::Frame)> {
        trace!(
            "Parse frame of size {} on stream ID {}",
            self.frame_payload_len,
            self.id
        );

        // Now we want to parse the whole frame payload but only if
        // there is enough data in our stream buffer.
        // stream.buf_bytes() should return an error if we don't have
        // enuough.
        let frame = Frame::from_bytes2(
            self.frame_type.unwrap(),
            self.frame_payload_len,
            self.buf_bytes(self.frame_payload_len as usize)?,
        )?;

        debug!("Parse {:?} on stream ID {}", frame, self.id);



        // TODO: bytes in the buffer are no longer needed, so we can remove them
        // and set the offset back to 0?
        self.buf_read_off += self.frame_payload_len;

        // Stream offset always increases, so we can track how many total bytes
        // we seen by the application layer
        self.stream_offset += self.frame_payload_len;

        // TODO: draft18+ will not got back to FramePayloadLenLen
        self.do_state_transition(StreamState::FramePayloadLenLen);
        Ok(frame)
    }

    pub fn more(&self) -> bool {
        let rem_bytes = self.buf_end_pos - self.buf_read_off - 1;
        trace!("Stream id {}: {} bytes remaining in buffer", self.id, rem_bytes);
        rem_bytes > 0
    }

}
