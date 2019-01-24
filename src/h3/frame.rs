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

use crate::Error;
use crate::Result;

use crate::octets;

use std::mem;

const ELEM_DEPENDENCY_TYPE_MASK: u8 = 0x30;

#[allow(dead_code)]
pub const DATA_FRAME_TYPE_ID: u8 = 0x0;
#[allow(dead_code)]
pub const HEADERS_FRAME_TYPE_ID: u8 = 0x1;
#[allow(dead_code)]
pub const PRIORITY_FRAME_TYPE_ID: u8 = 0x2;
#[allow(dead_code)]
pub const CANCEL_PUSH_FRAME_TYPE_ID: u8 = 0x3;
#[allow(dead_code)]
pub const SETTINGS_FRAME_TYPE_ID: u8 = 0x4;
#[allow(dead_code)]
pub const PUSH_PROMISE_FRAME_TYPE_ID: u8 = 0x5;
#[allow(dead_code)]
pub const GOAWAY_FRAME_TYPE_ID: u8 = 0x6;
#[allow(dead_code)]
pub const MAX_PUSH_FRAME_TYPE_ID: u8 = 0xD;
#[allow(dead_code)]
pub const DUPLICATE_PUSH_FRAME_TYPE_ID: u8 = 0xE;

/// HTTP/3 Prioritized Element type.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum PrioritizedElemType {
    RequestStream,
    PushStream,
    Placeholder,
    CurrentStream,
    Error,
}

impl PrioritizedElemType {
    fn is_peid_absent(self) -> bool {
        match self {
            PrioritizedElemType::CurrentStream => true,
            PrioritizedElemType::Error => true,
            _ => false,
        }
    }

    fn to_bits(self) -> u8 {
        match self {
            PrioritizedElemType::RequestStream => 0x00,
            PrioritizedElemType::PushStream => 0x01,
            PrioritizedElemType::Placeholder => 0x02,
            PrioritizedElemType::CurrentStream => 0x03,
            _ => 0x04,
        }
    }

    fn from_bits(bits: u8) -> PrioritizedElemType {
        match bits {
            0x00 => PrioritizedElemType::RequestStream,
            0x01 => PrioritizedElemType::PushStream,
            0x02 => PrioritizedElemType::Placeholder,
            0x03 => PrioritizedElemType::CurrentStream,
            _ => PrioritizedElemType::Error,
        }
    }
}

/// HTTP/3 Element Dependency type.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ElemDependencyType {
    RequestStream,
    PushStream,
    Placeholder,
    RootOfTree,
    Error,
}

impl ElemDependencyType {
    fn is_edid_absent(self) -> bool {
        match self {
            ElemDependencyType::RootOfTree => true,
            ElemDependencyType::Error => true,
            _ => false,
        }
    }

    fn to_bits(self) -> u8 {
        match self {
            ElemDependencyType::RequestStream => 0x00,
            ElemDependencyType::PushStream => 0x01,
            ElemDependencyType::Placeholder => 0x02,
            ElemDependencyType::RootOfTree => 0x03,
            _ => 0x04,
        }
    }

    fn from_bits(bits: u8) -> ElemDependencyType {
        match bits {
            0x00 => ElemDependencyType::RequestStream,
            0x01 => ElemDependencyType::PushStream,
            0x02 => ElemDependencyType::Placeholder,
            0x03 => ElemDependencyType::RootOfTree,
            _ => ElemDependencyType::Error,
        }
    }
}

#[derive(Clone, PartialEq)]
pub enum Frame {
    Data {
        payload: Vec<u8>,
    },

    Headers {
        header_block: Vec<u8>,
    },

    Priority {
        priority_elem: PrioritizedElemType,
        elem_dependency: ElemDependencyType,
        prioritized_element_id: Option<u64>,
        element_dependency_id: Option<u64>,
        weight: u8,
    },

    CancelPush {
        push_id: u64,
    },

    Settings {
        num_placeholders: Option<u64>,
        max_header_list_size: Option<u64>,
        qpack_max_table_capacity: Option<u64>,
        qpack_blocked_streams: Option<u64>,
    },

    PushPromise {
        push_id: u64,
        header_block: Vec<u8>,
    },

    GoAway {
        stream_id: u64,
    },

    MaxPushId {
        push_id: u64,
    },

    DuplicatePush {
        push_id: u64,
    },
}

impl Frame {
    pub fn from_bytes(b: &mut octets::Octets) -> Result<Frame> {
        let payload_length = b.get_varint()?;
        let frame_type = b.get_u8()?;

        // debug!("GOT FRAME {:x}, payload_len= {}", frame_type, payload_length);

        // TODO: handling of 0-length frames
        let frame = match frame_type {
            DATA_FRAME_TYPE_ID => Frame::Data {
                payload: b.get_bytes(payload_length as usize)?.to_vec(),
            },

            HEADERS_FRAME_TYPE_ID => Frame::Headers {
                header_block: b.get_bytes(payload_length as usize)?.to_vec(),
            },

            PRIORITY_FRAME_TYPE_ID => parse_priority_frame(b)?,

            CANCEL_PUSH_FRAME_TYPE_ID => Frame::CancelPush {
                push_id: b.get_varint()?,
            },

            SETTINGS_FRAME_TYPE_ID => parse_settings_frame(payload_length, b)?,

            PUSH_PROMISE_FRAME_TYPE_ID => parse_push_promise(payload_length, b)?,

            GOAWAY_FRAME_TYPE_ID => Frame::GoAway {
                stream_id: b.get_varint()?,
            },

            MAX_PUSH_FRAME_TYPE_ID => Frame::MaxPushId {
                push_id: b.get_varint()?,
            },

            DUPLICATE_PUSH_FRAME_TYPE_ID => Frame::DuplicatePush {
                push_id: b.get_varint()?,
            },

            _ => return Err(Error::InvalidFrame),
        };

        Ok(frame)
    }

    pub fn from_bytes2(
        frame_type: u8, payload_length: u64, bytes: &mut [u8],
    ) -> Result<Frame> {
        // let payload_length = b.get_varint()?;
        // let frame_type = b.get_u8()?;

        // debug!("GOT FRAME {:x}, payload_len= {}", frame_type, payload_length);
        // dbg!(&bytes);

        let mut b = octets::Octets::with_slice(bytes);

        // TODO: handling of 0-length frames
        let frame = match frame_type {
            0x0 => Frame::Data {
                payload: b.get_bytes(payload_length as usize)?.to_vec(),
            },

            0x1 => Frame::Headers {
                header_block: b.get_bytes(payload_length as usize)?.to_vec(),
            },

            0x02 => parse_priority_frame(&mut b)?,

            0x03 => Frame::CancelPush {
                push_id: b.get_varint()?,
            },

            0x04 => parse_settings_frame(payload_length, &mut b)?,

            0x05 => parse_push_promise(payload_length, &mut b)?,

            0x07 => Frame::GoAway {
                stream_id: b.get_varint()?,
            },

            0x0D => Frame::MaxPushId {
                push_id: b.get_varint()?,
            },

            0x0E => Frame::DuplicatePush {
                push_id: b.get_varint()?,
            },
            _ => {
                error!("Invalid frame type {}", frame_type);
                return Err(Error::InvalidFrame);
            },
        };

        Ok(frame)
    }

    pub fn to_bytes(&self, b: &mut octets::Octets) -> Result<usize> {
        let before = b.cap();

        trace!("Serializing frame type {:?}", self);

        match self {
            Frame::Data { payload } => {
                b.put_varint(payload.len() as u64)?;
                b.put_varint(0x00)?;

                b.put_bytes(payload.as_ref())?;
            },

            Frame::Headers { header_block } => {
                b.put_varint(header_block.len() as u64)?;
                b.put_varint(0x01)?;

                b.put_bytes(header_block.as_ref())?;
            },

            Frame::Priority {
                priority_elem,
                elem_dependency,
                prioritized_element_id,
                element_dependency_id,
                weight,
            } => {
                let mut length = 2 * mem::size_of::<u8>(); // 2 u8s = (PT+DT+Empty) + Weight
                if prioritized_element_id.is_some() {
                    length += octets::varint_len(prioritized_element_id.unwrap());
                }

                if element_dependency_id.is_some() {
                    length += octets::varint_len(element_dependency_id.unwrap());
                }

                b.put_varint(length as u64)?;
                b.put_varint(0x02)?;

                let mut bitfield = priority_elem.to_bits() << 6;
                bitfield |= elem_dependency.to_bits() << 4;

                b.put_u8(bitfield)?;

                if prioritized_element_id.is_some() {
                    b.put_varint(prioritized_element_id.unwrap())?;
                }
                if element_dependency_id.is_some() {
                    b.put_varint(element_dependency_id.unwrap())?;
                }

                b.put_u8(*weight)?;
            },

            Frame::CancelPush { push_id } => {
                b.put_varint(octets::varint_len(*push_id) as u64)?;
                b.put_varint(0x03)?;

                b.put_varint(*push_id)?;
            },

            Frame::Settings {
                num_placeholders,
                max_header_list_size,
                qpack_max_table_capacity,
                qpack_blocked_streams,
            } => {
                // TODO: make prettier
                let mut len = 0;

                if let Some(val) = num_placeholders {
                    len += mem::size_of::<u16>();
                    len += octets::varint_len(*val);
                }

                if let Some(val) = max_header_list_size {
                    len += mem::size_of::<u16>();
                    len += octets::varint_len(*val);
                }

                if let Some(val) = qpack_max_table_capacity {
                    len += mem::size_of::<u16>();
                    len += octets::varint_len(*val);
                }

                if let Some(val) = qpack_blocked_streams {
                    len += mem::size_of::<u16>();
                    len += octets::varint_len(*val);
                }

                trace!("SETTINGS payload will be {} bytes", len);

                b.put_varint(len as u64)?;
                b.put_varint(0x4)?;

                if let Some(val) = num_placeholders {
                        b.put_u16(0x8)?;
                        b.put_varint(*val as u64)?;
                }

                if let Some(val) = max_header_list_size {
                        b.put_u16(0x6)?;
                        b.put_varint(*val as u64)?;
                }

                if let Some(val) = qpack_max_table_capacity {
                        b.put_u16(0x1)?;
                        b.put_varint(*val as u64)?;
                }

                if let Some(val) = qpack_blocked_streams {
                        b.put_u16(0x7)?;
                        b.put_varint(*val as u64)?;
                }
            },

            Frame::PushPromise {
                push_id,
                header_block,
            } => {
                let len = octets::varint_len(*push_id) + header_block.len();
                b.put_varint(len as u64)?;
                b.put_varint(0x05)?;

                b.put_varint(*push_id)?;
                b.put_bytes(header_block.as_ref())?;
            },

            Frame::GoAway { stream_id } => {
                b.put_varint(octets::varint_len(*stream_id) as u64)?;
                b.put_varint(0x07)?;

                b.put_varint(*stream_id)?;
            },

            Frame::MaxPushId { push_id } => {
                b.put_varint(octets::varint_len(*push_id) as u64)?;
                b.put_varint(0x0D)?;

                b.put_varint(*push_id)?;
            },

            Frame::DuplicatePush { push_id } => {
                b.put_varint(octets::varint_len(*push_id) as u64)?;
                b.put_varint(0x0E)?;

                b.put_varint(*push_id)?;
            },
        }

        Ok(before - b.cap())
    }
}

impl std::fmt::Debug for Frame {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Frame::Data { payload } => {
                write!(f, "DATA len={}", payload.len())?;
            },

            Frame::Headers { header_block } => {
                write!(f, "HEADERS len={}", header_block.len())?;
            },

            Frame::Priority {
                priority_elem,
                elem_dependency,
                prioritized_element_id,
                element_dependency_id,
                weight,
            } => {
                let peid = match prioritized_element_id {
                    Some(x) => x.to_string(),
                    None => String::from("None"),
                };

                let edid = match element_dependency_id {
                    Some(x) => x.to_string(),
                    None => String::from("None"),
                };

                write!(f, "PRIORITY priority element type={:?} element dependency type={:?} prioritized element id={:?} element dependency id={:?} weight={:?}", priority_elem, elem_dependency, peid, edid, weight)?;
            },

            Frame::CancelPush { push_id } => {
                write!(f, "CANCEL_PUSH push id={}", push_id)?;
            },

            Frame::Settings {
                num_placeholders,
                max_header_list_size,
                qpack_max_table_capacity,
                qpack_blocked_streams,
            } => {
                write!(f, "SETTINGS num placeholders={:?}, max header list size={:?}, qpack max table capacity={:?}, qpack blocked streams={:?} ", num_placeholders, max_header_list_size, qpack_max_table_capacity, qpack_blocked_streams)?;
            },

            Frame::PushPromise {
                push_id,
                header_block,
            } => {
                write!(
                    f,
                    "PUSH_PROMISE push id={} len={}",
                    push_id,
                    header_block.len()
                )?;
            },

            Frame::GoAway { stream_id } => {
                write!(f, "GOAWAY stream id={}", stream_id)?;
            },

            Frame::MaxPushId { push_id } => {
                write!(f, "MAX_PUSH_ID push id={}", push_id)?;
            },

            Frame::DuplicatePush { push_id } => {
                write!(f, "DUPLICATE_PUSH push id={}", push_id)?;
            },
        }

        Ok(())
    }
}

fn parse_settings_frame(
    payload_length: u64, b: &mut octets::Octets,
) -> Result<Frame> {
    trace!(
        "Parsing SETTINGS frame with len {} and contents {:?}",
        payload_length,
        b
    );
    let mut num_placeholders = None;
    let mut max_header_list_size = None;
    let mut qpack_max_table_capacity = None;
    let mut qpack_blocked_streams = None;

    while b.off() < payload_length as usize {
        // TODO: ensure this exit condition is sane
        let setting = b.get_u16()?;

        match setting {
            0x1 => {
                qpack_max_table_capacity = Some(b.get_varint()?);
            },
            0x6 => {
                max_header_list_size = Some(b.get_varint()?);
            },
            0x7 => {
                qpack_blocked_streams = Some(b.get_varint()?);
            },
            0x8 => {
                num_placeholders = Some(b.get_varint()?);
            },
            _ => {
                error!("Setting parameter type {} not implemented!", setting);
                // Err(Error)
            },
        }
    }

    Ok(Frame::Settings {
        num_placeholders,
        max_header_list_size,
        qpack_max_table_capacity,
        qpack_blocked_streams,
    })
}

fn parse_priority_frame(b: &mut octets::Octets) -> Result<Frame> {
    let bitfield = b.get_u8()?;
    let mut prioritized_element_id = None;
    let mut element_dependency_id = None;

    let priority_elem = PrioritizedElemType::from_bits(bitfield >> 6);

    let elem_dependency = ElemDependencyType::from_bits(
        (bitfield & ELEM_DEPENDENCY_TYPE_MASK) >> 4,
    );

    if !priority_elem.is_peid_absent() {
        prioritized_element_id = Some(b.get_varint()?);
    }

    if !elem_dependency.is_edid_absent() {
        element_dependency_id = Some(b.get_varint()?);
    }

    let weight = b.get_u8()?;
    Ok(Frame::Priority {
        priority_elem,
        elem_dependency,
        prioritized_element_id,
        element_dependency_id,
        weight,
    })
}

fn parse_push_promise(
    payload_length: u64, b: &mut octets::Octets,
) -> Result<Frame> {
    let push_id = b.get_varint()?;
    let header_block_length = payload_length - octets::varint_len(push_id) as u64;
    let header_block = b.get_bytes(header_block_length as usize)?.to_vec();

    Ok(Frame::PushPromise {
        push_id,
        header_block,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data() {
        let mut d = [42; 128];

        let frame = Frame::Data {
            payload: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
        };

        let wire_len = {
            let mut b = octets::Octets::with_slice(&mut d);
            frame.to_bytes(&mut b).unwrap()
        };

        assert_eq!(wire_len, 14);

        let mut b = octets::Octets::with_slice(&mut d);
        assert_eq!(Frame::from_bytes(&mut b).unwrap(), frame);
    }

    #[test]
    fn headers() {
        let mut d = [42; 128];

        let frame = Frame::Headers {
            header_block: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
        };

        let wire_len = {
            let mut b = octets::Octets::with_slice(&mut d);
            frame.to_bytes(&mut b).unwrap()
        };

        assert_eq!(wire_len, 14);

        let mut b = octets::Octets::with_slice(&mut d);
        assert_eq!(Frame::from_bytes(&mut b).unwrap(), frame);
    }

    #[test]
    fn priority_current_stream_to_root() {
        let mut d = [42; 128];

        let frame = Frame::Priority {
            priority_elem: PrioritizedElemType::CurrentStream,
            elem_dependency: ElemDependencyType::RootOfTree,
            prioritized_element_id: None,
            element_dependency_id: None,
            weight: 16,
        };

        let wire_len = {
            let mut b = octets::Octets::with_slice(&mut d);
            frame.to_bytes(&mut b).unwrap()
        };

        assert_eq!(wire_len, 4);

        let mut b = octets::Octets::with_slice(&mut d);
        assert_eq!(Frame::from_bytes(&mut b).unwrap(), frame);
    }

    #[test]
    fn priority_placeholder_to_root() {
        let mut d = [42; 128];

        let frame = Frame::Priority {
            priority_elem: PrioritizedElemType::Placeholder,
            elem_dependency: ElemDependencyType::RootOfTree,
            prioritized_element_id: Some(0),
            element_dependency_id: None,
            weight: 16,
        };

        let wire_len = {
            let mut b = octets::Octets::with_slice(&mut d);
            frame.to_bytes(&mut b).unwrap()
        };

        assert_eq!(wire_len, 5);

        let mut b = octets::Octets::with_slice(&mut d);
        assert_eq!(Frame::from_bytes(&mut b).unwrap(), frame);
    }

    #[test]
    fn priority_current_stream_to_placeholder() {
        let mut d = [42; 128];

        let frame = Frame::Priority {
            priority_elem: PrioritizedElemType::CurrentStream,
            elem_dependency: ElemDependencyType::Placeholder,
            prioritized_element_id: None,
            element_dependency_id: Some(0),
            weight: 16,
        };

        let wire_len = {
            let mut b = octets::Octets::with_slice(&mut d);
            frame.to_bytes(&mut b).unwrap()
        };

        assert_eq!(wire_len, 5);

        let mut b = octets::Octets::with_slice(&mut d);
        assert_eq!(Frame::from_bytes(&mut b).unwrap(), frame);
    }

    #[test]
    fn priority_some_stream_to_placeholder() {
        let mut d = [42; 128];

        let frame = Frame::Priority {
            priority_elem: PrioritizedElemType::RequestStream,
            elem_dependency: ElemDependencyType::Placeholder,
            prioritized_element_id: Some(0x4),
            element_dependency_id: Some(0),
            weight: 16,
        };

        let wire_len = {
            let mut b = octets::Octets::with_slice(&mut d);
            frame.to_bytes(&mut b).unwrap()
        };

        assert_eq!(wire_len, 6);

        let mut b = octets::Octets::with_slice(&mut d);
        assert_eq!(Frame::from_bytes(&mut b).unwrap(), frame);
    }

    #[test]
    fn cancel_push() {
        let mut d = [42; 128];

        let frame = Frame::CancelPush { push_id: 0 };

        let wire_len = {
            let mut b = octets::Octets::with_slice(&mut d);
            frame.to_bytes(&mut b).unwrap()
        };

        assert_eq!(wire_len, 3);

        let mut b = octets::Octets::with_slice(&mut d);
        assert_eq!(Frame::from_bytes(&mut b).unwrap(), frame);
    }

    #[test]
    fn settings_all() {
        let mut d = [42; 128];

        let frame = Frame::Settings {
            num_placeholders: Some(16),
            max_header_list_size: Some(1024),
            qpack_max_table_capacity: Some(0),
            qpack_blocked_streams: Some(0),
        };

        let wire_len = {
            let mut b = octets::Octets::with_slice(&mut d);
            frame.to_bytes(&mut b).unwrap()
        };

        assert_eq!(wire_len, 15);

        let mut b = octets::Octets::with_slice(&mut d);
        assert_eq!(Frame::from_bytes(&mut b).unwrap(), frame);
    }

    #[test]
    fn settings_h3_only() {
        let mut d = [42; 128];

        let frame = Frame::Settings {
            num_placeholders: Some(16),
            max_header_list_size: Some(1024),
            qpack_max_table_capacity: None,
            qpack_blocked_streams: None,
        };

        let wire_len = {
            let mut b = octets::Octets::with_slice(&mut d);
            frame.to_bytes(&mut b).unwrap()
        };

        assert_eq!(wire_len, 9);

        let mut b = octets::Octets::with_slice(&mut d);
        assert_eq!(Frame::from_bytes(&mut b).unwrap(), frame);
    }

    #[test]
    fn settings_qpack_only() {
        let mut d = [42; 128];

        let frame = Frame::Settings {
            num_placeholders: None,
            max_header_list_size: None,
            qpack_max_table_capacity: Some(0),
            qpack_blocked_streams: Some(0),
        };

        let wire_len = {
            let mut b = octets::Octets::with_slice(&mut d);
            frame.to_bytes(&mut b).unwrap()
        };

        assert_eq!(wire_len, 8);

        let mut b = octets::Octets::with_slice(&mut d);
        assert_eq!(Frame::from_bytes(&mut b).unwrap(), frame);
    }

    #[test]
    fn push_promise() {
        let mut d = [42; 128];

        let frame = Frame::PushPromise {
            push_id: 0,
            header_block: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
        };

        let wire_len = {
            let mut b = octets::Octets::with_slice(&mut d);
            frame.to_bytes(&mut b).unwrap()
        };

        assert_eq!(wire_len, 15);

        let mut b = octets::Octets::with_slice(&mut d);
        assert_eq!(Frame::from_bytes(&mut b).unwrap(), frame);
    }

    #[test]
    fn goaway() {
        let mut d = [42; 128];

        let frame = Frame::GoAway { stream_id: 32 };

        let wire_len = {
            let mut b = octets::Octets::with_slice(&mut d);
            frame.to_bytes(&mut b).unwrap()
        };

        assert_eq!(wire_len, 3);

        let mut b = octets::Octets::with_slice(&mut d);
        assert_eq!(Frame::from_bytes(&mut b).unwrap(), frame);
    }

    #[test]
    fn max_push_id() {
        let mut d = [42; 128];

        let frame = Frame::MaxPushId { push_id: 128 };

        let wire_len = {
            let mut b = octets::Octets::with_slice(&mut d);
            frame.to_bytes(&mut b).unwrap()
        };

        assert_eq!(wire_len, 4);

        let mut b = octets::Octets::with_slice(&mut d);
        assert_eq!(Frame::from_bytes(&mut b).unwrap(), frame);
    }

    #[test]
    fn duplicate_push() {
        let mut d = [42; 128];

        let frame = Frame::DuplicatePush { push_id: 0 };

        let wire_len = {
            let mut b = octets::Octets::with_slice(&mut d);
            frame.to_bytes(&mut b).unwrap()
        };

        assert_eq!(wire_len, 3);

        let mut b = octets::Octets::with_slice(&mut d);
        assert_eq!(Frame::from_bytes(&mut b).unwrap(), frame);
    }
}
