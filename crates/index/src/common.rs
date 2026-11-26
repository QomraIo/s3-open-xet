//! Conversions and checks every backend shares, so SQLite and Postgres
//! store, refuse and report the same values the same way.

use std::collections::HashMap;

use openxet_protocol::MerkleHash;

#[cfg(feature = "fault-injection")]
use crate::FAULT_AFTER_FIRST_FILE_SCOPE;
use crate::{ChunkLayout, IndexError, Term};

pub(crate) fn to_i64(value: u64, what: &str) -> Result<i64, IndexError> {
    i64::try_from(value)
        .map_err(|_| IndexError::InvalidInput(format!("{what} {value} is over i64::MAX")))
}

pub(crate) fn to_u64(value: i64, what: &str) -> Result<u64, IndexError> {
    u64::try_from(value).map_err(|_| IndexError::Corrupt(format!("{what} is negative ({value})")))
}

pub(crate) fn to_usize(value: i64, what: &str) -> Result<usize, IndexError> {
    usize::try_from(value)
        .map_err(|_| IndexError::Corrupt(format!("{what} {value} is not a valid count")))
}

/// Fails `register_shard` after its first file for
/// [`FAULT_AFTER_FIRST_FILE_SCOPE`].
#[cfg(feature = "fault-injection")]
pub(crate) fn fault_point(file_index: usize, scope: &str) -> Result<(), IndexError> {
    if file_index == 0 && scope == FAULT_AFTER_FIRST_FILE_SCOPE {
        return Err(IndexError::InjectedFault);
    }
    Ok(())
}

#[cfg(not(feature = "fault-injection"))]
#[expect(
    clippy::unnecessary_wraps,
    reason = "matches the fault-injection build"
)]
pub(crate) fn fault_point(_file_index: usize, _scope: &str) -> Result<(), IndexError> {
    Ok(())
}

/// Maps a foreign-key violation from writing a row that names `xorb` to
/// [`IndexError::UnknownXorb`]: the xorb isn't stored, which retrying won't
/// fix, so the generic database error would mislead.
pub(crate) fn unknown_xorb_on_fk_violation(e: IndexError, xorb: MerkleHash) -> IndexError {
    match e {
        IndexError::Database(sqlx::Error::Database(db)) if db.is_foreign_key_violation() => {
            IndexError::UnknownXorb { xorb }
        }
        other => other,
    }
}

/// Each term's stored bytes, `[offsets[chunk_start], offsets[chunk_end])`
/// in its xorb, from `layouts`, which hold every xorb `terms` name.
pub(crate) fn term_bytes(
    terms: &[Term],
    layouts: &HashMap<MerkleHash, ChunkLayout>,
) -> Result<Vec<(u32, u32)>, IndexError> {
    terms
        .iter()
        .map(|t| {
            let offsets = &layouts
                .get(&t.xorb)
                .ok_or(IndexError::UnknownXorb { xorb: t.xorb })?
                .offsets;
            match (
                offsets.get(t.chunk_start as usize),
                offsets.get(t.chunk_end as usize),
            ) {
                (Some(&start), Some(&end)) if start < end => Ok((start, end)),
                _ => Err(IndexError::InvalidInput(format!(
                    "a term names chunks {}..{} of xorb {}, which has {} chunks",
                    t.chunk_start,
                    t.chunk_end,
                    t.xorb,
                    offsets.len().saturating_sub(1)
                ))),
            }
        })
        .collect()
}
