#[repr(u8)]
#[non_exhaustive]
#[derive(Debug,Clone)]
pub enum ValueType {
	Uint8 = 0,
	Uint16 = 1,
	Uint32 = 2,
	Uint64 = 3,
	String = 4,
	Object = 5,
	Bytes = 6,
}