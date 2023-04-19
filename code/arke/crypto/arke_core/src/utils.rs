#[macro_export]
/// Generate a random alphanumeric string of fixed length.
macro_rules! random_id {
    ($length:expr) => {
        thread_rng()
            .sample_iter(&Alphanumeric)
            .take($length)
            .map(char::from)
            .collect::<String>()
    };
}

/// Convert a string length into the number of underlying bytes.
///
/// Caution (Nico): currently it seems that passing the same number works fine but haven't found confirmation of this yet.
pub(crate) fn string_length_to_byte_length(string_length: usize) -> usize {
    string_length
}
