use crate::{
	Result,
	ZffError,
	ZffErrorKind,
	FILE_EXTENSION_START,
	FILE_EXTENSION_PARSER_ERROR,
};

pub fn file_extension_next_value<V: Into<String>>(value: V) -> Result<String> {
	let value = value.into();

	let mut chars = value.chars();
	match chars.next() {
		Some(FILE_EXTENSION_START) => (),
		_ => return Err(ZffError::new(ZffErrorKind::FileExtensionParserError, FILE_EXTENSION_PARSER_ERROR)),
	};
	let mut next_value: u64 = match chars.as_str().parse() {
		Ok(val) => val,
		Err(e) => return Err(ZffError::new(ZffErrorKind::FileExtensionParserError, e.to_string())),
	};
	next_value += 1;
	if next_value <= 99 {
		return Ok(String::from("z0") + &next_value.to_string())
	} else {
		Ok(String::from("z") + &next_value.to_string())
	}
}