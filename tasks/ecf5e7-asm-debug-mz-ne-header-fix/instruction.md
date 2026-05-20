# Internal Debug Task: DOS MZ/NE Executable Analyzer

The core analyzer for MZ (pure DOS) and NE (Windows 1.x‑3.x) executable formats is implemented in x86‑64 assembly. The source files in `/app/src/` have been corrupted and need restoration.

## Observed Symptoms

- The analyzer crashes when parsing certain executable headers.
- NE segment table enumeration produces garbled offset values.
- Relocation table parsing misreports entry counts or segment references.
- Final statistics output appears malformed under some input conditions.

## Requirements

The program reads:
- `argv[1]` – path to a binary executable file
- `argv[2]` – mode string (`headers`, `segments`, or `relocs`)

## Format Specifications (Internal Reference)

**MZ header (first 28 bytes):**
- `magic` (2B): `'MZ'` (0x4D 0x5A)
- `bytes_last_page` (2B LE)
- `pages_in_file` (2B LE)
- `num_relocations` (2B LE)
- `header_paragraphs` (2B LE)
- `min_extra` (2B LE)
- `max_extra` (2B LE)
- `initial_ss` (2B LE)
- `initial_sp` (2B LE)
- `checksum` (2B LE)
- `initial_ip` (2B LE)
- `initial_cs` (2B LE)
- `reloc_table_offset` (2B LE)
- `overlay_number` (2B LE)

- Offset `0x3C` (4 bytes LE) points to the NE header when non‑zero.

**NE header (starts with magic `'NE'`):**
- `linker_version` (2B LE)
- `entry_table_offset` (2B LE)
- `entry_table_length` (2B LE)
- `crc` (4B LE)
- `flags` (2B LE)
- `auto_data_segment` (2B LE)
- `heap_init` (2B LE)
- `stack_init` (2B LE)
- `entry_point` (4B LE, segment:offset)
- `stack_pointer` (4B LE)
- `segment_count` (2B LE)
- `module_ref_count` (2B LE)
- `nonres_name_size` (2B LE)
- `segment_table_offset` (2B LE)
- `resource_table_offset` (2B LE)
- `resident_name_offset` (2B LE)
- `module_ref_offset` (2B LE)
- `import_name_offset` (2B LE)
- `nonres_name_offset` (4B LE)
- `moveable_entries` (2B LE)
- `alignment_shift` (2B LE)
- `resource_segments` (2B LE)
- `target_os` (1B)
- `flags2` (1B)
- `fastload_area` (4B LE)
- `fastload_size` (2B LE)
- `reserved` (2B)
- `expected_windows_version` (2B LE)

**Segment table entry (8 bytes each):**
- `sector_offset` (2B LE) – multiply by `2^alignment_shift` to get byte offset
- `length` (2B LE)
- `flags` (2B LE)
- `min_alloc` (2B LE)

## Output Format

### Mode `headers`
- `MZ pages=PP relocs=RR entry=SSSS:OOOO`
  - `PP`, `RR`: 4‑digit decimal (zero‑padded)
  - `SSSS:OOOO`: uppercase 4‑digit hex (no `0x` prefix)
- If NE present: `NE segments=SS modules=MM entry=SSSS:OOOO` (same formatting)

### Mode `segments`
- One line per segment: `SEG NN off=OOOOOOOO len=LLLL flags=FFFF type=CODE` or `type=DATA`
  - `NN`: 2‑digit decimal (zero‑padded)
  - `OOOOOOOO`: 8‑digit uppercase hex (byte offset)
  - `LLLL`: 4‑digit uppercase hex (length)
  - `FFFF`: 4‑digit uppercase hex (flags)
  - `type`: `CODE` if bit 0 of flags is set, otherwise `DATA`

### Mode `relocs`
- MZ relocation entries: `RELOC seg=SSSS off=OOOO` (both 4‑digit uppercase hex)

### Final summary line (all modes)
- `EXECUTABLE type=MZ code=CCCC data=DDDD relocs=RRRR`
- or `type=NE`
- `CCCC`, `DDDD`, `RRRR`: 4‑digit decimal (total code bytes, data bytes, relocation count)

## Error Handling

Exit code `1` with output `ERROR: reason` where `reason` is one of:
- `bad_magic`
- `bad_ne_offset`
- `truncated`
- `file_not_found`

## Build & Verification Requirements

- All corrupted assembly files are in `/app/src/`
- Fixed source must compile with:
