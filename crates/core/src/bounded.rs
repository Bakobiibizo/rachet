//! Variable-length consensus containers with compile-time protocol maxima.

use bytes::{Buf, BufMut};
use commonware_codec::{EncodeSize, Error as CodecError, RangeCfg, Read, Write};
use core::fmt;

/// Construction failed because a variable-length value exceeded its protocol maximum.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LengthExceeded {
    maximum: usize,
    actual: usize,
}

impl LengthExceeded {
    const fn new(maximum: usize, actual: usize) -> Self {
        Self { maximum, actual }
    }

    /// Returns the protocol maximum.
    pub const fn maximum(self) -> usize {
        self.maximum
    }

    /// Returns the rejected length.
    pub const fn actual(self) -> usize {
        self.actual
    }
}

impl fmt::Display for LengthExceeded {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "length {} exceeds protocol maximum {}",
            self.actual, self.maximum
        )
    }
}

impl std::error::Error for LengthExceeded {}

/// A byte string whose length cannot exceed `MAX`.
///
/// Its canonical decoder validates the wire length before allocating payload
/// storage. Mutable access to the backing vector is deliberately not exposed.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct BoundedBytes<const MAX: usize>(Vec<u8>);

impl<const MAX: usize> BoundedBytes<MAX> {
    /// The largest value representable by Commonware's portable length prefix.
    const WIRE_MAX_ASSERTION: () = assert!(MAX <= u32::MAX as usize);

    /// Validates and constructs bounded bytes.
    pub fn new(bytes: Vec<u8>) -> Result<Self, LengthExceeded> {
        let () = Self::WIRE_MAX_ASSERTION;
        if bytes.len() > MAX {
            return Err(LengthExceeded::new(MAX, bytes.len()));
        }
        Ok(Self(bytes))
    }

    /// Returns the protocol maximum.
    pub const fn maximum_len() -> usize {
        let () = Self::WIRE_MAX_ASSERTION;
        MAX
    }

    /// Returns the number of bytes.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns whether the value contains no bytes.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns the bounded bytes as a slice.
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    /// Consumes the wrapper and returns its backing vector.
    pub fn into_inner(self) -> Vec<u8> {
        self.0
    }
}

impl<const MAX: usize> Default for BoundedBytes<MAX> {
    fn default() -> Self {
        let () = Self::WIRE_MAX_ASSERTION;
        Self(Vec::new())
    }
}

impl<const MAX: usize> AsRef<[u8]> for BoundedBytes<MAX> {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl<const MAX: usize> TryFrom<Vec<u8>> for BoundedBytes<MAX> {
    type Error = LengthExceeded;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        Self::new(bytes)
    }
}

impl<const MAX: usize> TryFrom<&[u8]> for BoundedBytes<MAX> {
    type Error = LengthExceeded;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        Self::new(bytes.to_vec())
    }
}

impl<const MAX: usize> From<BoundedBytes<MAX>> for Vec<u8> {
    fn from(bytes: BoundedBytes<MAX>) -> Self {
        bytes.into_inner()
    }
}

impl<const MAX: usize> Write for BoundedBytes<MAX> {
    fn write(&self, buf: &mut impl BufMut) {
        let () = Self::WIRE_MAX_ASSERTION;
        self.0.write(buf);
    }
}

impl<const MAX: usize> EncodeSize for BoundedBytes<MAX> {
    fn encode_size(&self) -> usize {
        let () = Self::WIRE_MAX_ASSERTION;
        self.0.encode_size()
    }
}

impl<const MAX: usize> Read for BoundedBytes<MAX> {
    type Cfg = ();

    fn read_cfg(buf: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
        let () = Self::WIRE_MAX_ASSERTION;
        let bytes = Vec::<u8>::read_cfg(buf, &(RangeCfg::new(..=MAX), ()))?;
        Ok(Self(bytes))
    }
}

/// A vector whose element count cannot exceed `MAX`.
///
/// The canonical decoder validates the advertised count before reserving the
/// vector. Each element's own decoder remains responsible for bounding its
/// nested variable-length fields.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(transparent)]
pub struct BoundedVec<T, const MAX: usize>(Vec<T>);

impl<T, const MAX: usize> BoundedVec<T, MAX> {
    /// The largest value representable by Commonware's portable length prefix.
    const WIRE_MAX_ASSERTION: () = assert!(MAX <= u32::MAX as usize);

    /// Validates and constructs a bounded vector.
    pub fn new(values: Vec<T>) -> Result<Self, LengthExceeded> {
        let () = Self::WIRE_MAX_ASSERTION;
        if values.len() > MAX {
            return Err(LengthExceeded::new(MAX, values.len()));
        }
        Ok(Self(values))
    }

    /// Returns the protocol maximum element count.
    pub const fn maximum_len() -> usize {
        let () = Self::WIRE_MAX_ASSERTION;
        MAX
    }

    /// Returns the element count.
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns whether the vector contains no elements.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Returns the elements as a slice.
    pub fn as_slice(&self) -> &[T] {
        &self.0
    }

    /// Returns an iterator over the elements.
    pub fn iter(&self) -> core::slice::Iter<'_, T> {
        self.0.iter()
    }

    /// Appends one element if capacity under the protocol maximum remains.
    pub fn try_push(&mut self, value: T) -> Result<(), LengthExceeded> {
        let actual = self.0.len().saturating_add(1);
        if actual > MAX {
            return Err(LengthExceeded::new(MAX, actual));
        }
        self.0.push(value);
        Ok(())
    }

    /// Consumes the wrapper and returns its backing vector.
    pub fn into_inner(self) -> Vec<T> {
        self.0
    }
}

impl<T, const MAX: usize> Default for BoundedVec<T, MAX> {
    fn default() -> Self {
        let () = Self::WIRE_MAX_ASSERTION;
        Self(Vec::new())
    }
}

impl<T, const MAX: usize> AsRef<[T]> for BoundedVec<T, MAX> {
    fn as_ref(&self) -> &[T] {
        self.as_slice()
    }
}

impl<T, const MAX: usize> TryFrom<Vec<T>> for BoundedVec<T, MAX> {
    type Error = LengthExceeded;

    fn try_from(values: Vec<T>) -> Result<Self, Self::Error> {
        Self::new(values)
    }
}

impl<T, const MAX: usize> From<BoundedVec<T, MAX>> for Vec<T> {
    fn from(values: BoundedVec<T, MAX>) -> Self {
        values.into_inner()
    }
}

impl<T, const MAX: usize> IntoIterator for BoundedVec<T, MAX> {
    type Item = T;
    type IntoIter = std::vec::IntoIter<T>;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a, T, const MAX: usize> IntoIterator for &'a BoundedVec<T, MAX> {
    type Item = &'a T;
    type IntoIter = core::slice::Iter<'a, T>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<T: Write, const MAX: usize> Write for BoundedVec<T, MAX> {
    fn write(&self, buf: &mut impl BufMut) {
        let () = Self::WIRE_MAX_ASSERTION;
        self.0.write(buf);
    }
}

impl<T: EncodeSize, const MAX: usize> EncodeSize for BoundedVec<T, MAX> {
    fn encode_size(&self) -> usize {
        let () = Self::WIRE_MAX_ASSERTION;
        self.0.encode_size()
    }
}

impl<T: Read, const MAX: usize> Read for BoundedVec<T, MAX> {
    type Cfg = T::Cfg;

    fn read_cfg(buf: &mut impl Buf, cfg: &Self::Cfg) -> Result<Self, CodecError> {
        let () = Self::WIRE_MAX_ASSERTION;
        let values = Vec::<T>::read_cfg(buf, &(RangeCfg::new(..=MAX), cfg.clone()))?;
        Ok(Self(values))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::{Decode, Encode};
    use core::sync::atomic::{AtomicBool, Ordering};

    #[test]
    fn construction_and_mutation_enforce_exact_boundaries() {
        let bytes = BoundedBytes::<3>::new(vec![1, 2, 3]).expect("boundary is valid");
        assert_eq!(bytes.as_slice(), [1, 2, 3]);
        let error = BoundedBytes::<3>::new(vec![1, 2, 3, 4]).expect_err("oversized");
        assert_eq!(error.maximum(), 3);
        assert_eq!(error.actual(), 4);

        let mut values = BoundedVec::<u8, 2>::new(vec![1]).expect("within bound");
        values.try_push(2).expect("boundary is valid");
        assert_eq!(values.as_slice(), [1, 2]);
        assert_eq!(values.try_push(3), Err(LengthExceeded::new(2, 3)));
        assert_eq!(values.as_slice(), [1, 2]);
    }

    #[test]
    fn canonical_vectors_and_round_trips_are_stable() {
        let bytes = BoundedBytes::<3>::new(vec![1, 2, 3]).unwrap();
        assert_eq!(bytes.encode().as_ref(), &[0x03, 0x01, 0x02, 0x03]);
        assert_eq!(
            BoundedBytes::<3>::decode_cfg(bytes.encode(), &()).unwrap(),
            bytes
        );

        let values = BoundedVec::<u16, 2>::new(vec![0x1234, 0xabcd]).unwrap();
        assert_eq!(values.encode().as_ref(), &[0x02, 0x12, 0x34, 0xab, 0xcd]);
        assert_eq!(
            BoundedVec::<u16, 2>::decode_cfg(values.encode(), &()).unwrap(),
            values
        );
    }

    #[test]
    fn oversized_lengths_fail_before_payload_or_element_decode() {
        assert!(matches!(
            BoundedBytes::<8>::decode_cfg([0x09].as_slice(), &()),
            Err(CodecError::InvalidLength(9))
        ));

        // The maximum portable u32 length must be rejected from its prefix alone,
        // rather than attempted as a multi-gigabyte allocation.
        assert!(matches!(
            BoundedBytes::<8>::decode_cfg([0xff, 0xff, 0xff, 0xff, 0x0f].as_slice(), &()),
            Err(CodecError::InvalidLength(length)) if length == u32::MAX as usize
        ));

        static ELEMENT_READ_CALLED: AtomicBool = AtomicBool::new(false);

        #[derive(Debug)]
        struct AllocationProbe;

        impl Read for AllocationProbe {
            type Cfg = ();

            fn read_cfg(_: &mut impl Buf, _: &Self::Cfg) -> Result<Self, CodecError> {
                ELEMENT_READ_CALLED.store(true, Ordering::SeqCst);
                Err(CodecError::EndOfBuffer)
            }

            fn read_vec(
                _: &mut impl Buf,
                _: usize,
                _: &Self::Cfg,
            ) -> Result<Vec<Self>, CodecError> {
                ELEMENT_READ_CALLED.store(true, Ordering::SeqCst);
                Err(CodecError::EndOfBuffer)
            }
        }

        assert!(matches!(
            BoundedVec::<AllocationProbe, 8>::decode_cfg([0x09].as_slice(), &()),
            Err(CodecError::InvalidLength(9))
        ));
        assert!(!ELEMENT_READ_CALLED.load(Ordering::SeqCst));
    }

    #[test]
    fn malformed_truncated_and_trailing_inputs_are_rejected() {
        assert!(matches!(
            BoundedBytes::<8>::decode_cfg([0x80, 0x80, 0x80, 0x80, 0x80].as_slice(), &()),
            Err(CodecError::InvalidVarint(_) | CodecError::InvalidUsize)
        ));
        assert!(matches!(
            BoundedBytes::<8>::decode_cfg([0x03, 0x01, 0x02].as_slice(), &()),
            Err(CodecError::EndOfBuffer)
        ));
        assert!(matches!(
            BoundedVec::<u16, 2>::decode_cfg([0x02, 0x00, 0x01].as_slice(), &()),
            Err(CodecError::EndOfBuffer)
        ));
        assert!(matches!(
            BoundedBytes::<8>::decode_cfg([0x01, 0x07, 0x08].as_slice(), &()),
            Err(CodecError::ExtraData(1))
        ));
    }
}
