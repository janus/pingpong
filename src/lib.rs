
use std::net::UdpSocket;
use std::time::{Duration, SystemTime, Instant};
use std::vec::Vec;
use std::net::Ipv6Addr;
use bytes::BufMut;
use std::io::Cursor;
use std::error::Error;
use std::{fmt, io};
use byteorder::{BigEndian, ReadBytesExt};
use std::collections::HashMap;

#[derive(Debug)]
pub enum MessageError {
    /// Doesn't have enough bytes to decode a correct message
    InvalidPayloadError,
    /// Insufficient bytes in to decode a full message
    BufferUnderflow,
    /// Unknown message code indicates a possible unsupported message
    InvalidMagic,
    /// General I/O error
    IoError(io::Error),
    /// MSG_IM_HERE: Received IP address is invalid
    InvalidIpAddress,
}




trait HelloR {
    fn connect(ip: &'static str, port: &'static str) ->  Self;
    fn send(&self, kind: u8) -> Self;
    fn receive(&self) -> &'static str;
}

struct TimeKeeper {
    sentWithTime: Duration,
    arrivalTime: Duration
}

struct RTT {
    table: Option<HashMap<Ipv6Addr,Vec<u64>>
    socket : UdpSocket
}

const HELLO_HEADER: u8 = 0x01;
const HELLO_LEN: u16 = 27;
const IHU_HEADER: u8 = 0x02;
const IHU_LEN: u16 = 35;


impl RTT {

    fn new(ip: &'static str, port: &'static str) -> Self {
        let socket = UdpSocket::bind(format!("{}:{}", ip, port)).expect("couldn't bind to address");
        // create table
        RTT {
            socket: socket,
            table: None
        }

    }

    fn send(&self, buf: &mut[u8], recipient: UdpSocket) {
        self.socket.send_to(buf, recipient)?;
    }

    fn receive(&self, buf: &mut[u8]) -> UdpSocket {
        self.socket.recv_from(buf)?;

    }

    fn decode(header: MessageHeader, buf: &mut[u8]) -> Instant {
        if buf.is_empty() {
            trace!("Received an empty ImHere packet!");
            return Err(MessageError::InvalidPayloadError);
        }

        let mut pointer = Cursor::new(&buf);
        let packet_header = pointer.read_u8()?;

        match packet_header {
            HELLO_HEADER => {
                let packet_size = pointer.read_u16::<BigEndian>()?;
                if packet_size < HELLO_LEN {
                    trace!(
                        "Received an ImHere packet with an invalid size: {:?}",
                        packet_size
                    );
                    return Err(MessageError::BufferUnderflow);
                }

                let mut peer_address_arr: [u16; 8] = [0xFFFF; 8];
                for i in (0..8).rev() {
                    peer_address_arr[i] = pointer.read_u16::<BigEndian>()?;
                }
                let peer_address = Ipv6Addr::new(
                    peer_address_arr[7],
                    peer_address_arr[6],
                    peer_address_arr[5],
                    peer_address_arr[4],
                    peer_address_arr[3],
                    peer_address_arr[2],
                    peer_address_arr[1],
                    peer_address_arr[0],
                );

                if peer_address.is_unspecified() || peer_address.is_loopback()|| peer_address.is_multicast(){
                    trace!(
                        "Received a valid ImHere with an invalid ip address: {:?}",
                        peer_address,
                    );
                    return Err(MessageError::InvalidIpAddress);
                }

                let sent_timestamp = pointer.read_u64::<BigEndian>()?; // store to table

                if self.table.is_none() {
                    self.table = HashMap::new();
                }

                let local_timestamp = SystemTime::now();
                let since_the_epoch = local_timestamp.duration_since(SystemTime::UNIX_EPOCH).expect("Time went backwards");
                let local_timestamp_in_ms = since_the_epoch.as_secs() * 1000 +
                    since_the_epoch.subsec_nanos() as u64 / 1_000_000;

                let vec_of_timestamps = vec![sent_timestamp, local_timestamp_in_ms];
                self.table.insert(peer_address, vec_of_timestamps)
                trace!("ImHere decoding completed successfully {:?}", buf);

            }
            IHU_HEADER => {
                let packet_size = pointer.read_u16::<BigEndian>()?;
                if packet_size < IHU_LEN {
                    trace!(
                        "Received an ImHere packet with an invalid size: {:?}",
                        packet_size
                    );
                    return Err(MessageError::BufferUnderflow);
                }

                let mut peer_address_arr: [u16; 8] = [0xFFFF; 8];
                for i in (0..8).rev() {
                    peer_address_arr[i] = pointer.read_u16::<BigEndian>()?;
                }
                let peer_address = Ipv6Addr::new(
                    peer_address_arr[7],
                    peer_address_arr[6],
                    peer_address_arr[5],
                    peer_address_arr[4],
                    peer_address_arr[3],
                    peer_address_arr[2],
                    peer_address_arr[1],
                    peer_address_arr[0],
                );

                if peer_address.is_unspecified() || peer_address.is_loopback()|| peer_address.is_multicast(){
                    trace!(
                        "Received a valid ImHere with an invalid ip address: {:?}",
                        peer_address,
                    );
                    return Err(MessageError::InvalidIpAddress);
                }

                let firstTimeStamp = pointer.read_u64::<BigEndian>()?; // store to table
                let secondTimeStamp = pointer.read_u64::<BigEndian>()?;

                trace!("ImHere decoding completed successfully {:?}", buf);

            }
        }


    }

    fn encode(&mut self, header: u8, addr: Ipv6Addr) -> Vec<u8> {
        let mut buf = Vec::new();
        let start = SystemTime::now();
        let since_the_epoch = start.duration_since(SystemTime::UNIX_EPOCH).expect("Time went backwards");
        let in_ms = since_the_epoch.as_secs() * 1000 +
            since_the_epoch.subsec_nanos() as u64 / 1_000_000;
        
         match header {
            HELLO_HEADER => {
                buf.put_u8(HELLO_HEADER);
                buf.put_u16_be(HELLO_LEN);
                let ipaddr_bytes: [u8; 16] = addr.octets();
                for i in ipaddr_bytes.iter() {
                    buf.put_u8(*i);
                }
                buf.put_u64(in_ms);
                return buf

            }
            IHU => {
                buf.put_u8(IHU)
                buf.put_u16_be(IHU_LEN)
                let ipaddr_bytes: [u8; 16] = addr.octets();
                for i in ipaddr_bytes.iter() {
                    buf.put_u8(*i);
                }
                buf.put_u64_be(in_ms);
                bu.put_u64_be(in_ms) // should come from store value (neighbour table)
                return buf;
            }
            _ => {println!("Wrong protocol header");
                  return buf;
            }

         }
    }
    fn process(&self, buf: &mut[u8]) {

        match buf[0] {
            1 =>  {
                let sentTIme = this.decode(Hello, buf[1..])

            }

            2 => {

            }

            _ => {
                println!("Unknown package")
            }
        }
    }

    // add code here
}


#[cfg(test)]
mod tests {
    super::.;

    struct DummyConn {}

    impl Hellor for HelloR{

        // add code here
    }
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}
