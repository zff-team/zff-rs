// - Parent
use super::*;

// - external

// Will copy a redb to another redb.
pub(crate) fn copy_redb(input_db: &Database, output_db: &mut Database) -> Result<()> {
	// prepare read context of input_db
	let read_txn = input_db.begin_read()?;
	let read_table = read_txn.open_table(PRELOADED_CHUNK_OFFSET_MAP_TABLE)?;
	let mut table_iterator = read_table.iter()?;

	// prepare write context of output_db
	let write_txn = output_db.begin_write()?;
	let mut write_table = write_txn.open_table(PRELOADED_CHUNK_OFFSET_MAP_TABLE)?;

	while let Some(data) = table_iterator.next_back() {
		let (key, value) = data?;
		write_table.insert(key.value(), value.value())?;
	}

	// prepare read context of input_db
	let read_table = read_txn.open_table(PRELOADED_CHUNK_SIZE_MAP_TABLE)?;
	let mut table_iterator = read_table.iter()?;
	let mut write_table = write_txn.open_table(PRELOADED_CHUNK_SIZE_MAP_TABLE)?;

	while let Some(data) = table_iterator.next_back() {
		let (key, value) = data?;
		write_table.insert(key.value(), value.value())?;
	}

	// prepare read context of input_db
	let read_table = read_txn.open_table(PRELOADED_CHUNK_FLAGS_MAP_TABLE)?;
	let mut table_iterator = read_table.iter()?;
	let mut write_table = write_txn.open_table(PRELOADED_CHUNK_FLAGS_MAP_TABLE)?;

	while let Some(data) = table_iterator.next_back() {
		let (key, value) = data?;
		write_table.insert(key.value(), value.value())?;
	}
	
	// prepare read context of input_db
	let read_table = read_txn.open_table(PRELOADED_CHUNK_CRC_MAP_TABLE)?;
	let mut table_iterator = read_table.iter()?;
	let mut write_table = write_txn.open_table(PRELOADED_CHUNK_CRC_MAP_TABLE)?;

	while let Some(data) = table_iterator.next_back() {
		let (key, value) = data?;
		let buf = value.value();
		write_table.insert(key.value(), buf)?;
	}

	// prepare read context of input_db
	let read_table = read_txn.open_table(PRELOADED_CHUNK_SAME_BYTES_MAP_TABLE)?;
	let mut table_iterator = read_table.iter()?;
	let mut write_table = write_txn.open_table(PRELOADED_CHUNK_SAME_BYTES_MAP_TABLE)?;

	while let Some(data) = table_iterator.next_back() {
		let (key, value) = data?;
		write_table.insert(key.value(), value.value())?;
	}

	// prepare read context of input_db
	let read_table = read_txn.open_table(PRELOADED_CHUNK_DUPLICATION_MAP_TABLE)?;
	let mut table_iterator = read_table.iter()?;
	let mut write_table = write_txn.open_table(PRELOADED_CHUNK_DUPLICATION_MAP_TABLE)?;

	while let Some(data) = table_iterator.next_back() {
		let (key, value) = data?;
		write_table.insert(key.value(), value.value())?;
	}
	
	Ok(())
}

pub(crate) fn convert_in_memory_preloaded_chunkmaps_into_redb(db: &mut Database, maps: &PreloadedChunkMapsInMemory) -> Result<()> {
	initialize_redb_table_offset_map(db, &maps.offsets)?;
	initialize_redb_table_size_map(db, &maps.sizes)?;
	initialize_redb_table_flags_map(db, &maps.flags)?;
	initialize_redb_table_crc_map(db, &maps.crcs)?;
	initialize_redb_table_samebytes_map(db, &maps.same_bytes)?;
	initialize_redb_table_dedup_map(db, &maps.duplicate_chunks)?;
	Ok(())
}

pub(crate) fn initialize_redb_table_offset_map(db: &mut Database, map: &HashMap<u64, u64>) -> Result<()> {
	let write_txn = db.begin_write()?;
	{
		let mut table = write_txn.open_table(PRELOADED_CHUNK_OFFSET_MAP_TABLE)?;
		for (key, value) in map {
			table.insert(key, value)?;
		}
	}
	write_txn.commit()?;
	Ok(())
}

pub(crate) fn initialize_redb_table_size_map(db: &mut Database, map: &HashMap<u64, u64>) -> Result<()> {
	let write_txn = db.begin_write()?;
	{
		let mut table = write_txn.open_table(PRELOADED_CHUNK_SIZE_MAP_TABLE)?;
		for (key, value) in map {
			table.insert(key, value)?;
		}
	}
	write_txn.commit()?;
	Ok(())
}

pub(crate) fn initialize_redb_table_flags_map(db: &mut Database, map: &HashMap<u64, ChunkFlags>) -> Result<()> {
	let write_txn = db.begin_write()?;
	{
		let mut table = write_txn.open_table(PRELOADED_CHUNK_FLAGS_MAP_TABLE)?;
		for (key, value) in map {
			table.insert(key, value.as_bytes())?;
		}
	}
	write_txn.commit()?;
	Ok(())
}

pub(crate) fn initialize_redb_table_crc_map(db: &mut Database, map: &HashMap<u64, u32>) -> Result<()> {
	let write_txn = db.begin_write()?;
	{
		let mut table = write_txn.open_table(PRELOADED_CHUNK_CRC_MAP_TABLE)?;
		for (key, value) in map {
			table.insert(key, value)?;
		}
	}
	write_txn.commit()?;
	Ok(())
}

pub(crate) fn initialize_redb_table_samebytes_map(db: &mut Database, map: &HashMap<u64, u8>) -> Result<()> {
	let write_txn = db.begin_write()?;
	{
		let mut table = write_txn.open_table(PRELOADED_CHUNK_SAME_BYTES_MAP_TABLE)?;
		for (key, value) in map {
			table.insert(key, value)?;
		}
	}
	write_txn.commit()?;
	Ok(())
}

pub(crate) fn initialize_redb_table_dedup_map(db: &mut Database, map: &HashMap<u64, u64>) -> Result<()> {
	let write_txn = db.begin_write()?;
	{
		let mut table = write_txn.open_table(PRELOADED_CHUNK_DUPLICATION_MAP_TABLE)?;
		for (key, value) in map {
			table.insert(key, value)?;
		}
	}
	write_txn.commit()?;
	Ok(())
}

pub(crate) fn convert_redb_into_in_memory_preloaded_chunkmaps(db: &mut Database) -> Result<PreloadedChunkMapsInMemory> {
	let offset_map = extract_redb_offset_map(db)?;
	let size_map = extract_redb_size_map(db)?;
	let flags_map = extract_redb_flags_map(db)?;
	let crc_map = extract_redb_crc_map(db)?;
	let samebytes_map = extract_redb_samebytes_map(db)?;
	let dedup_map = extract_redb_dedup_map(db)?;
	Ok(PreloadedChunkMapsInMemory::with_data(
		offset_map, size_map, flags_map, crc_map, samebytes_map, dedup_map))
}

pub(crate) fn extract_redb_offset_map(db: &mut Database) -> Result<HashMap<u64, u64>> {
	let mut new_map = HashMap::new();
	let read_txn = db.begin_read()?;
	let table = read_txn.open_table(PRELOADED_CHUNK_OFFSET_MAP_TABLE)?;
	let mut table_iterator = table.iter()?;
	while let Some(data) = table_iterator.next_back() {
		let (key, value) = data?;
		new_map.insert(key.value(), value.value());
	}
	Ok(new_map)
}

pub(crate) fn extract_redb_size_map(db: &mut Database) -> Result<HashMap<u64, u64>> {
	let mut new_map = HashMap::new();
	let read_txn = db.begin_read()?;
	let table = read_txn.open_table(PRELOADED_CHUNK_SIZE_MAP_TABLE)?;
	let mut table_iterator = table.iter()?;
	while let Some(data) = table_iterator.next_back() {
		let (key, value) = data?;
		new_map.insert(key.value(), value.value());
	}
	Ok(new_map)
}

pub(crate) fn extract_redb_flags_map(db: &mut Database) -> Result<HashMap<u64, ChunkFlags>> {
	let mut new_map = HashMap::new();
	let read_txn = db.begin_read()?;
	let table = read_txn.open_table(PRELOADED_CHUNK_FLAGS_MAP_TABLE)?;
	let mut table_iterator = table.iter()?;
	while let Some(data) = table_iterator.next_back() {
		let (key, value) = data?;
		let flags = ChunkFlags::from(value.value());
		new_map.insert(key.value(), flags);
	}
	Ok(new_map)
}

pub(crate) fn extract_redb_crc_map(db: &mut Database) -> Result<HashMap<u64, u32>> {
	let mut new_map = HashMap::new();
	let read_txn = db.begin_read()?;
	let table = read_txn.open_table(PRELOADED_CHUNK_CRC_MAP_TABLE)?;
	let mut table_iterator = table.iter()?;
	while let Some(data) = table_iterator.next_back() {
		let (key, value) = data?;
		new_map.insert(key.value(), value.value());
	}
	Ok(new_map)
}

pub(crate) fn extract_redb_samebytes_map(db: &mut Database) -> Result<HashMap<u64, u8>> {
	let mut new_map = HashMap::new();
	let read_txn = db.begin_read()?;
	let table = read_txn.open_table(PRELOADED_CHUNK_SAME_BYTES_MAP_TABLE)?;
	let mut table_iterator = table.iter()?;
	while let Some(data) = table_iterator.next_back() {
		let (key, value) = data?;
		new_map.insert(key.value(), value.value());
	}
	Ok(new_map)
}

pub(crate) fn extract_redb_dedup_map(db: &mut Database) -> Result<HashMap<u64, u64>> {
	let mut new_map = HashMap::new();
	let read_txn = db.begin_read()?;
	let table = read_txn.open_table(PRELOADED_CHUNK_DUPLICATION_MAP_TABLE)?;
	let mut table_iterator = table.iter()?;
	while let Some(data) = table_iterator.next_back() {
		let (key, value) = data?;
		new_map.insert(key.value(), value.value());
	}
	Ok(new_map)
}