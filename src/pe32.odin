package main

import "core:fmt"
import "core:os"
import "core:bytes"
import "core:slice"
import "core:mem"
import "core:math"

/*
Handy References:
- https://llvm.org/docs/PDB/MsfFile.html
- https://github.com/dotnet/runtime/blob/main/docs/design/specs/PE-COFF.md
- https://pierrelib.pagesperso-orange.fr/exec_formats/MS_Symbol_Type_v1.0.pdf
*/

DOS_MAGIC  := []u8{ 0x4d, 0x5a }
PE32_MAGIC := []u8{ 'P', 'E', 0, 0 }

DEBUG_TYPE_CODEVIEW :: 2

COFF_Header :: struct #packed {
	machine:              u16,
	section_count:        u16,
	timestamp:            u32,
	symbol_table_offset:  u32,
	symbol_count:         u32,
	optional_header_size: u16,
	flags:                u16,
}

Data_Directory :: struct #packed {
	virtual_addr: u32,
	size:         u32,
}

COFF_Optional_Header :: struct #packed {
	magic:                u16,
	linker_major_version:  u8,
	linker_minor_version:  u8,
	code_size:            u32,
	init_data_size:       u32,
	uninit_data_size:     u32,
	entrypoint_addr:      u32,
	code_base:            u32,
	image_base:           u64,
	section_align:        u32,
	file_align:           u32,
	os_major_version:     u16,
	os_minor_version:     u16,
	image_major_version:  u16,
	image_minor_version:  u16,
	subsystem_major_version: u16,
	subsystem_minor_version: u16,
	win32_version:        u32,
	image_size:           u32,
	headers_size:         u32,
	checksum:             u32,
	subsystem:            u16,
	dll_flags:            u16,
	reserve_stack_size:   u64,
	commit_stack_size:    u64,
	reserve_heap_size:    u64,
	commit_heap_size:     u64,
	loader_flags:         u32,
	rva_and_sizes_count:  u32,
	data_directories:     [16]Data_Directory,
}

COFF_Section_Header :: struct #packed {
	name:             [8]u8,
	virtual_size:       u32,
	virtual_addr:       u32,
	raw_data_size:      u32,
	raw_data_offset:    u32,
	reloc_offset:       u32,
	line_number_offset: u32,
	relocation_count:   u16,
	line_number_count:  u16,
	flags:              u32,
}

PE32_Header :: struct #packed {
	magic: [4]u8,
	coff_header: COFF_Header,
	optional_header: COFF_Optional_Header,
}

COFF_Debug_Directory :: struct #packed {
	flags:           u32,
	timestamp:       u32,
	major_version:   u16,
	minor_version:   u16,
	type:            u32,
	data_size:       u32,
	raw_data_addr:   u32,
	raw_data_offset: u32,
}

COFF_Debug_Entry :: struct #packed {
	signature: [4]u8,
	guid:     [16]u8,
	age:         u32,
}

load_pe32 :: proc(trace: ^Trace, exec_buffer: []u8) -> bool {
	pdb_path := ""
	dos_end_offset := 0x3c
	pe_hdr_offset := slice_to_type(exec_buffer[dos_end_offset:], u32) or_return

	cur_offset := int(pe_hdr_offset)
	pe_hdr := slice_to_type(exec_buffer[cur_offset:], PE32_Header) or_return

	if !bytes.equal(pe_hdr.magic[:], PE32_MAGIC) {
		return false
	}

	cur_offset += size_of(PE32_Header)
	section_buffer := exec_buffer[cur_offset:]
	section_bytes := (size_of(COFF_Section_Header) * int(pe_hdr.coff_header.section_count))

	// 6 is always debug
	debug_rva := pe_hdr.optional_header.data_directories[6].virtual_addr
	for i := 0; i < int(pe_hdr.coff_header.section_count); i += 1 {
		section_offset := i * size_of(COFF_Section_Header)
		section_hdr := slice_to_type(section_buffer[section_offset:], COFF_Section_Header) or_return

		start := section_hdr.virtual_addr
		end   := start + section_hdr.virtual_size
		if debug_rva < start || (debug_rva + size_of(COFF_Debug_Directory)) > end {
			continue
		}

		section_relative_offset := debug_rva - start
		dir_offset := section_hdr.raw_data_offset + section_relative_offset
		debug_dir := slice_to_type(exec_buffer[dir_offset:], COFF_Debug_Directory) or_return
		if debug_dir.type != DEBUG_TYPE_CODEVIEW {
			break
		}

		if debug_dir.data_size <= size_of(COFF_Debug_Entry) {
			break
		}

		pdb_path = string(cstring(raw_data(exec_buffer[debug_dir.raw_data_offset+size_of(COFF_Debug_Entry):])))
		break
	}
	if pdb_path == "" {
		return false
	}

	fmt.printf("PDB is at %s\n", pdb_path)
	pdb_buffer := os.read_entire_file_from_filename(pdb_path) or_return
	defer delete(pdb_buffer)

	return load_pdb(trace, section_buffer, pdb_buffer)
}
