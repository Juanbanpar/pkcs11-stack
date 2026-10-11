// SPDX-License-Identifier: MIT OR Apache-2.0
use crate::Error;
use zeroize::Zeroizing;

pub(crate) fn unreserved(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"-._~".contains(&b)
}

pub(crate) fn decode(value: &str, query: bool) -> Result<Zeroizing<Vec<u8>>, Error> {
    let mut out = Zeroizing::new(Vec::with_capacity(value.len()));
    let mut bytes = value.bytes();
    while let Some(b) = bytes.next() {
        if b == b'%' {
            let high = bytes.next().and_then(hex).ok_or(Error::PercentEncoding)?;
            let low = bytes.next().and_then(hex).ok_or(Error::PercentEncoding)?;
            out.push(high * 16 + low);
        } else if unreserved(b)
            || b":[]@!$'()*+,=".contains(&b)
            || (query && b"/?|".contains(&b))
            || (!query && b == b'&')
        {
            out.push(b);
        } else {
            return Err(Error::Character);
        }
    }
    Ok(out)
}

fn hex(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

pub(crate) fn encode(out: &mut String, value: &[u8], binary: bool) {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for &b in value {
        if !binary && unreserved(b) {
            out.push(char::from(b));
        } else {
            out.push('%');
            out.push(char::from(HEX[usize::from(b >> 4)]));
            out.push(char::from(HEX[usize::from(b & 15)]));
        }
    }
}

pub(crate) fn encoded_len(value: &[u8], binary: bool) -> usize {
    value
        .iter()
        .map(|&b| if !binary && unreserved(b) { 1 } else { 3 })
        .sum()
}
