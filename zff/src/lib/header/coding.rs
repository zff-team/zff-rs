pub enum ValueType {
	Uint8,
	Uint32,
	Uint64,
	String,
	Object,
}

impl ValueType {
	pub fn as_raw_value(&self) -> u8 {
		match self {
			ValueType::Uint8 => 0,
			ValueType::Uint32 => 1,
			ValueType::Uint64 => 2,
			ValueType::String => 3,
			ValueType::Object => 4,
		}
	}
}