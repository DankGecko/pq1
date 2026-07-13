//! Shared, strict ELF-to-flash-image reconstruction.
//!
//! Both the human-facing `fwmeasure` command and the release signer consume
//! this implementation.  A release ELF is accepted only when every non-empty
//! `PT_LOAD` segment is wholly contained in the measured flash envelope.  No
//! segment is silently skipped or clipped: doing so would let the displayed
//! measurement and signed package omit bytes the ELF asks a loader to place.

#![forbid(unsafe_code)]

use object::elf::PT_LOAD;
use object::read::elf::{ElfFile32, ProgramHeader};
use object::{LittleEndian, Object, ObjectSymbol};
use sha2::{Digest, Sha256};
use std::error::Error;
use std::fmt;
use std::path::Path;

/// Maximum plausible contiguous flash measurement region (2 MiB).
pub const MAX_FLASH_SIZE: u64 = 2 * 1024 * 1024;

/// Optional explicit measurement envelope overrides.
///
/// Overrides may enlarge or relocate the enclosing window, but they never
/// authorize dropping part of a non-empty load segment.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LayoutOverrides {
    pub flash_base: Option<u64>,
    pub flash_end: Option<u64>,
}

/// Result of flattening an ELF into its measured flash image.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FlatImage {
    pub bytes: Vec<u8>,
    pub base: u64,
    pub hash: [u8; 32],
}

impl FlatImage {
    /// Image byte length, narrowed to the manifest's field type.
    #[must_use]
    pub fn len(&self) -> u32 {
        u32::try_from(self.bytes.len()).expect("flat image larger than 4 GiB")
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    #[must_use]
    pub fn end(&self) -> u64 {
        self.base + self.bytes.len() as u64
    }
}

/// A deterministic diagnostic for malformed or unsafe ELF layouts.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FlattenError(String);

impl FlattenError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for FlattenError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Error for FlattenError {}

struct LoadSegment<'a> {
    index: usize,
    start: u64,
    end: u64,
    data: &'a [u8],
}

/// Read and strictly flatten an ELF using its canonical measurement envelope.
pub fn flatten_elf(path: &Path) -> Result<FlatImage, FlattenError> {
    flatten_elf_with_overrides(path, LayoutOverrides::default())
}

/// Read and strictly flatten an ELF with explicit envelope overrides.
pub fn flatten_elf_with_overrides(
    path: &Path,
    overrides: LayoutOverrides,
) -> Result<FlatImage, FlattenError> {
    let data = std::fs::read(path)
        .map_err(|e| FlattenError::new(format!("Cannot read ELF {}: {e}", path.display())))?;
    flatten_elf_bytes_with_overrides(path, &data, overrides)
}

/// Strictly flatten an immutable in-memory ELF snapshot.
pub fn flatten_elf_bytes(path: &Path, data: &[u8]) -> Result<FlatImage, FlattenError> {
    flatten_elf_bytes_with_overrides(path, data, LayoutOverrides::default())
}

/// Strict byte-slice variant with explicit envelope overrides.
pub fn flatten_elf_bytes_with_overrides(
    path: &Path,
    elf_data: &[u8],
    overrides: LayoutOverrides,
) -> Result<FlatImage, FlattenError> {
    let elf = ElfFile32::<LittleEndian>::parse(elf_data)
        .map_err(|e| FlattenError::new(format!("parsing ELF {}: {e}", path.display())))?;
    let le = LittleEndian;

    // Collect and validate all non-empty load headers before choosing or
    // allocating the measurement window.  A malformed endpoint must fail
    // before it can influence a truncated hash or a large allocation.
    let mut loads = Vec::new();
    for (index, ph) in elf.elf_program_headers().iter().enumerate() {
        if ph.p_type(le) != PT_LOAD || ph.p_filesz(le) == 0 {
            continue;
        }
        let start = u64::from(ph.p_paddr(le));
        let file_size = u64::from(ph.p_filesz(le));
        let end = start.checked_add(file_size).ok_or_else(|| {
            FlattenError::new(format!(
                "{}: PT_LOAD #{index} endpoint overflows: {start:#x} + {file_size:#x}",
                path.display()
            ))
        })?;
        let segment_data = ph.data(le, elf_data).map_err(|_| {
            FlattenError::new(format!(
                "{}: cannot read PT_LOAD #{index} at {start:#x}",
                path.display()
            ))
        })?;
        let expected_len = usize::try_from(file_size).map_err(|_| {
            FlattenError::new(format!(
                "{}: PT_LOAD #{index} length does not fit usize: {file_size}",
                path.display()
            ))
        })?;
        if segment_data.len() != expected_len {
            return Err(FlattenError::new(format!(
                "{}: PT_LOAD #{index} data length {} differs from p_filesz {expected_len}",
                path.display(),
                segment_data.len()
            )));
        }
        loads.push(LoadSegment {
            index,
            start,
            end,
            data: segment_data,
        });
    }
    if loads.is_empty() {
        return Err(FlattenError::new(format!(
            "{}: No LOAD segments found in ELF",
            path.display()
        )));
    }

    let find_symbol = |name: &str| -> Option<u64> {
        elf.symbols()
            .find(|symbol| symbol.name() == Ok(name))
            .map(|symbol| symbol.address())
    };
    let require_symbol = |name: &str| -> Result<u64, FlattenError> {
        find_symbol(name)
            .ok_or_else(|| FlattenError::new(format!("{}: missing {name} symbol", path.display())))
    };

    // The vector table is the linked runtime image base and therefore the
    // only safe default for measurement/signing.  Deriving the base from the
    // lowest PT_LOAD would let a stray early segment shift the package while
    // leaving the firmware's reset vectors at their original address.
    let vector_base = require_symbol("__vector_table")?;
    if !loads.iter().any(|segment| segment.start == vector_base) {
        return Err(FlattenError::new(format!(
            "{}: __vector_table ({vector_base:#x}) is not the start of a non-empty PT_LOAD",
            path.display()
        )));
    }
    let base = overrides.flash_base.unwrap_or(vector_base);
    let flash_window_end = base.checked_add(MAX_FLASH_SIZE).ok_or_else(|| {
        FlattenError::new(format!(
            "{}: flash window endpoint overflows from base {base:#x}",
            path.display()
        ))
    })?;

    let end = if let Some(end) = overrides.flash_end {
        end
    } else if let Some(veneer_limit) =
        find_symbol("__veneer_limit").filter(|limit| (base..flash_window_end).contains(limit))
    {
        veneer_limit
    } else {
        let sidata = require_symbol("__sidata")?;
        let sdata = require_symbol("__sdata")?;
        let edata = require_symbol("__edata")?;
        let data_size = edata.checked_sub(sdata).ok_or_else(|| {
            FlattenError::new(format!(
                "{}: __edata ({edata:#x}) precedes __sdata ({sdata:#x})",
                path.display()
            ))
        })?;
        sidata.checked_add(data_size).ok_or_else(|| {
            FlattenError::new(format!(
                "{}: fallback measurement endpoint overflows: {sidata:#x} + {data_size:#x}",
                path.display()
            ))
        })?
    };

    let size_u64 = end.checked_sub(base).ok_or_else(|| {
        FlattenError::new(format!(
            "{}: measurement end ({end:#x}) precedes base ({base:#x})",
            path.display()
        ))
    })?;
    if size_u64 == 0 {
        return Err(FlattenError::new(format!(
            "{}: empty measurement envelope at {base:#x}",
            path.display()
        )));
    }
    if size_u64 > MAX_FLASH_SIZE {
        return Err(FlattenError::new(format!(
            "{}: measurement envelope is {size_u64} bytes, above the {MAX_FLASH_SIZE}-byte limit",
            path.display()
        )));
    }

    for segment in &loads {
        if segment.start < base || segment.end > end {
            return Err(FlattenError::new(format!(
                "{}: PT_LOAD #{} [{:#x}, {:#x}) is outside measurement envelope [{base:#x}, {end:#x})",
                path.display(),
                segment.index,
                segment.start,
                segment.end
            )));
        }
    }

    let size = usize::try_from(size_u64).map_err(|_| {
        FlattenError::new(format!(
            "{}: measurement length does not fit usize: {size_u64}",
            path.display()
        ))
    })?;
    let mut flash = vec![0xFFu8; size];
    for segment in loads {
        let offset_u64 = segment.start.checked_sub(base).ok_or_else(|| {
            FlattenError::new(format!(
                "{}: PT_LOAD #{} offset underflow",
                path.display(),
                segment.index
            ))
        })?;
        let offset = usize::try_from(offset_u64).map_err(|_| {
            FlattenError::new(format!(
                "{}: PT_LOAD #{} offset does not fit usize",
                path.display(),
                segment.index
            ))
        })?;
        let copy_end = offset.checked_add(segment.data.len()).ok_or_else(|| {
            FlattenError::new(format!(
                "{}: PT_LOAD #{} copy endpoint overflows",
                path.display(),
                segment.index
            ))
        })?;
        if copy_end > flash.len() {
            return Err(FlattenError::new(format!(
                "{}: PT_LOAD #{} escaped validated envelope",
                path.display(),
                segment.index
            )));
        }
        flash[offset..copy_end].copy_from_slice(segment.data);
    }

    let hash: [u8; 32] = Sha256::digest(&flash).into();
    Ok(FlatImage {
        bytes: flash,
        base,
        hash,
    })
}
