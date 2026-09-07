// - Parent
use super::*;

/// Opens a table for reading, treating a table that does not exist as empty.
///
/// A redb database contains no tables until a write transaction creates them,
/// so reading from a database that has not been filled yet must not fail. This
/// happens whenever a caller selects the redb backed chunkmap mode and switches
/// away again before anything has been preloaded.
fn open_optional_table<K, V>(
    read_txn: &redb::ReadTransaction,
    definition: redb::TableDefinition<'_, K, V>,
) -> Result<Option<redb::ReadOnlyTable<K, V>>>
where
    K: redb::Key + 'static,
    V: redb::Value + 'static,
{
    match read_txn.open_table(definition) {
        Ok(table) => Ok(Some(table)),
        Err(redb::TableError::TableDoesNotExist(_)) => Ok(None),
        Err(e) => Err(e.into()),
    }
}

// Will copy a redb to another redb.
pub(crate) fn copy_redb(input_db: &Database, output_db: &mut Database) -> Result<()> {
    // prepare read context of input_db
    let read_txn = input_db.begin_read()?;

    // prepare write context of output_db
    let write_txn = output_db.begin_write()?;

    if let Some(read_table) = open_optional_table(&read_txn, PRELOADED_CHUNK_OFFSET_MAP_TABLE)? {
        let mut table_iterator = read_table.iter()?;
        let mut write_table = write_txn.open_table(PRELOADED_CHUNK_OFFSET_MAP_TABLE)?;

        while let Some(data) = table_iterator.next_back() {
            let (key, value) = data?;
            write_table.insert(key.value(), value.value())?;
        }
    }

    // prepare read context of input_db
    if let Some(read_table) = open_optional_table(&read_txn, PRELOADED_CHUNK_SIZE_MAP_TABLE)? {
        let mut table_iterator = read_table.iter()?;
        let mut write_table = write_txn.open_table(PRELOADED_CHUNK_SIZE_MAP_TABLE)?;

        while let Some(data) = table_iterator.next_back() {
            let (key, value) = data?;
            write_table.insert(key.value(), value.value())?;
        }
    }

    // prepare read context of input_db
    if let Some(read_table) = open_optional_table(&read_txn, PRELOADED_CHUNK_FLAGS_MAP_TABLE)? {
        let mut table_iterator = read_table.iter()?;
        let mut write_table = write_txn.open_table(PRELOADED_CHUNK_FLAGS_MAP_TABLE)?;

        while let Some(data) = table_iterator.next_back() {
            let (key, value) = data?;
            write_table.insert(key.value(), value.value())?;
        }
    }

    // prepare read context of input_db
    if let Some(read_table) = open_optional_table(&read_txn, PRELOADED_CHUNK_XXHASH_MAP_TABLE)? {
        let mut table_iterator = read_table.iter()?;
        let mut write_table = write_txn.open_table(PRELOADED_CHUNK_XXHASH_MAP_TABLE)?;

        while let Some(data) = table_iterator.next_back() {
            let (key, value) = data?;
            let buf = value.value();
            write_table.insert(key.value(), buf)?;
        }
    }

    // prepare read context of input_db
    if let Some(read_table) = open_optional_table(&read_txn, PRELOADED_CHUNK_SAME_BYTES_MAP_TABLE)?
    {
        let mut table_iterator = read_table.iter()?;
        let mut write_table = write_txn.open_table(PRELOADED_CHUNK_SAME_BYTES_MAP_TABLE)?;

        while let Some(data) = table_iterator.next_back() {
            let (key, value) = data?;
            write_table.insert(key.value(), value.value())?;
        }
    }

    // prepare read context of input_db
    if let Some(read_table) = open_optional_table(&read_txn, PRELOADED_CHUNK_DUPLICATION_MAP_TABLE)?
    {
        let mut table_iterator = read_table.iter()?;
        let mut write_table = write_txn.open_table(PRELOADED_CHUNK_DUPLICATION_MAP_TABLE)?;

        while let Some(data) = table_iterator.next_back() {
            let (key, value) = data?;
            write_table.insert(key.value(), value.value())?;
        }
    }

    Ok(())
}

pub(crate) fn convert_in_memory_preloaded_chunkmaps_into_redb(
    db: &mut Database,
    maps: &PreloadedChunkMapsInMemory,
) -> Result<()> {
    initialize_redb_table_chunk_header_map(db, &maps.chunk_header)?;
    initialize_redb_table_samebytes_map(db, &maps.same_bytes)?;
    initialize_redb_table_dedup_map(db, &maps.duplicate_chunks)?;
    Ok(())
}

pub(crate) fn initialize_redb_table_chunk_header_map(
    db: &mut Database,
    map: &HashMap<u64, ChunkHeader>,
) -> Result<()> {
    let write_txn = db.begin_write()?;
    {
        let mut table_offset = write_txn.open_table(PRELOADED_CHUNK_OFFSET_MAP_TABLE)?;
        let mut table_size = write_txn.open_table(PRELOADED_CHUNK_SIZE_MAP_TABLE)?;
        let mut table_flags = write_txn.open_table(PRELOADED_CHUNK_FLAGS_MAP_TABLE)?;
        let mut table_integrity_hash = write_txn.open_table(PRELOADED_CHUNK_XXHASH_MAP_TABLE)?;
        for (key, value) in map {
            table_offset.insert(key, value.offset)?;
            table_size.insert(key, value.size)?;
            table_flags.insert(key, value.flags.as_bytes())?;
            table_integrity_hash.insert(key, value.integrity_hash)?;
        }
    }
    write_txn.commit()?;
    Ok(())
}

pub(crate) fn initialize_redb_table_samebytes_map(
    db: &mut Database,
    map: &HashMap<u64, u8>,
) -> Result<()> {
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

pub(crate) fn initialize_redb_table_dedup_map(
    db: &mut Database,
    map: &HashMap<u64, u64>,
) -> Result<()> {
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

pub(crate) fn convert_redb_into_in_memory_preloaded_chunkmaps(
    db: &mut Database,
) -> Result<PreloadedChunkMapsInMemory> {
    let chunk_header_map = extract_redb_chunk_header_map(db)?;
    let samebytes_map = extract_redb_samebytes_map(db)?;
    let dedup_map = extract_redb_dedup_map(db)?;
    Ok(PreloadedChunkMapsInMemory::new(
        chunk_header_map,
        samebytes_map,
        dedup_map,
    ))
}

pub(crate) fn extract_redb_chunk_header_map(
    db: &mut Database,
) -> Result<HashMap<u64, ChunkHeader>> {
    let mut new_map = HashMap::new();
    let read_txn = db.begin_read()?;
    let (Some(table_offset), Some(table_size), Some(table_flags), Some(table_integrity_hash)) = (
        open_optional_table(&read_txn, PRELOADED_CHUNK_OFFSET_MAP_TABLE)?,
        open_optional_table(&read_txn, PRELOADED_CHUNK_SIZE_MAP_TABLE)?,
        open_optional_table(&read_txn, PRELOADED_CHUNK_FLAGS_MAP_TABLE)?,
        open_optional_table(&read_txn, PRELOADED_CHUNK_XXHASH_MAP_TABLE)?,
    ) else {
        // Nothing has been preloaded into this database yet.
        return Ok(new_map);
    };
    let mut table_iterator = table_offset.iter()?;
    while let Some(offset_data) = table_iterator.next_back() {
        let (chunk_no, offset) = offset_data?;
        let size = table_size
            .get(chunk_no.value())?
            .ok_or(ZffError::new(ZffErrorKind::DatabaseError, ERROR_NOT_IN_MAP))?;
        let flags = table_flags
            .get(chunk_no.value())?
            .ok_or(ZffError::new(ZffErrorKind::DatabaseError, ERROR_NOT_IN_MAP))?;
        let integrity_hash = table_integrity_hash
            .get(chunk_no.value())?
            .ok_or(ZffError::new(ZffErrorKind::DatabaseError, ERROR_NOT_IN_MAP))?;
        let chunk_header = ChunkHeader::new(
            offset.value(),
            size.value(),
            ChunkFlags::from(flags.value()),
            integrity_hash.value(),
        );
        new_map.insert(chunk_no.value(), chunk_header);
    }
    Ok(new_map)
}

pub(crate) fn extract_redb_samebytes_map(db: &mut Database) -> Result<HashMap<u64, u8>> {
    let mut new_map = HashMap::new();
    let read_txn = db.begin_read()?;
    let Some(table) = open_optional_table(&read_txn, PRELOADED_CHUNK_SAME_BYTES_MAP_TABLE)? else {
        // Nothing has been preloaded into this database yet.
        return Ok(new_map);
    };
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
    let Some(table) = open_optional_table(&read_txn, PRELOADED_CHUNK_DUPLICATION_MAP_TABLE)? else {
        // Nothing has been preloaded into this database yet.
        return Ok(new_map);
    };
    let mut table_iterator = table.iter()?;
    while let Some(data) = table_iterator.next_back() {
        let (key, value) = data?;
        new_map.insert(key.value(), value.value());
    }
    Ok(new_map)
}
