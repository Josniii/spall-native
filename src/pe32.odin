package main

import "core:fmt"
import "core:os"
import "core:bytes"
import "core:slice"
import "core:mem"
import "core:math"

/*
For this file:

Copyright 2023 Colin Davidson

Permission is hereby granted, free of charge, to any person obtaining a copy of this file, to deal in the file without restriction,
including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the file,
and to permit persons to whom the file is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/

/*
Handy References:
- https://llvm.org/docs/PDB/MsfFile.html
- https://github.com/dotnet/runtime/blob/main/docs/design/specs/PE-COFF.md
- https://pierrelib.pagesperso-orange.fr/exec_formats/MS_Symbol_Type_v1.0.pdf
*/

DOS_MAGIC  := []u8{ 0x4d, 0x5a }
PE32_MAGIC := []u8{ 'P', 'E', 0, 0 }
PDB_MAGIC := []u8{
	'M', 'i', 'c', 'r', 'o', 's', 'o', 'f', 't', ' ', 'C', '/', 'C', '+', '+',
	' ', 'M', 'S', 'F', ' ', '7', '.', '0', '0', '\r', '\n', 0x1A, 0x44, 0x53, 0, 0, 0,
}

DEBUG_TYPE_CODEVIEW :: 2
DBI_STREAM_IDX :: 3

PDB_V70 :: 19990903


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

PDB_MSF_Header :: struct #packed {
	magic:           [32]u8,
	block_size:         u32,
	free_block_map_idx: u32,
	block_count:        u32,
	directory_size:     u32,
	reserved:           u32,
}

PDB_DBI_Header :: struct #packed {
	signature:                  i32,
	version:                    u32,
	age:                        u32,
	global_stream_idx:          u16,
	build_idx:                  u16,
	public_stream_idx:          u16,
	pdb_dll_version:            u16,
	sym_record_stream:          u16,
	pdb_dll_rebuild:            u16,
	mod_info_size:              i32,
	section_contrib_size:       i32,
	section_map_size:           i32,
	source_info_size:           i32,
	type_server_size:           i32,
	mfc_type_server_idx:        u32,
	optional_debug_header_size: i32,
	ec_subsystem_size:          i32,
	flags:                      u16,
	machine:                    u16,
	pad:                        u32,
}

PDB_Named_Stream_Map :: struct #packed {
	length:              u32,
}

PDB_Section_Contrib_Entry :: struct #packed {
	section:    u16,
	padding:  [2]u8,
	offset:     i32,
	size:       i32,
	flags:      u32,
	module_idx: u16,
	padding2: [2]u8,
	data_crc:   u32,
	reloc_crc:  u32,
}

PDB_Module_Info :: struct #packed {
	reserved:             u32,
	section_contrib:      PDB_Section_Contrib_Entry,
	flags:                u16,
	module_symbol_stream: u16,
	symbols_size:         u32,
	c11_size:             u32,
	c13_size:             u32,
	source_file_count:    u16,
	padding:            [2]u8,
	reserved2:            u32,
	source_file_name_idx: u32,
	file_path_name_idx:   u32,
}

PDB_Stream_Header :: struct #packed {
	signature: u32,
	version:   u32,
	size:      u32,
	guid:   [16]u8,
}

PDB_Symbol_Header :: struct #packed {
	length: u16,
	type: CV_Symbol_Type,
}

CV_Symbol_Type :: enum u16 {
	GlobalProc32 = 0x1110,
	LocalProc32  = 0x110f,
}

CV_Proc32 :: struct #packed {
	record_length:    u16,
	record_type:      u16,
	parent_offset:    u32,
	block_end_offset: u32,
	next_offset:      u32,
	proc_length:      u32,
	dbg_start_offset: u32,
	dbg_end_offset:   u32,
	type_id:          u32,
	offset:           u32,
	section_idx:      u16,
	flags:             u8,
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

	msf_hdr := slice_to_type(pdb_buffer, PDB_MSF_Header) or_return
	if !bytes.equal(msf_hdr.magic[:], PDB_MAGIC) {
		return false
	}

	// PDB is complete nonsense. 
	// At the bottom of the PDB header is an array of offsets. The array of offsets get you blocks, containing offsets.
	// *THOSE* offsets get you the blocks containing the data to figure out what your data is.

	directory_block_count := div_ceil(msf_hdr.directory_size, msf_hdr.block_size)
	msf_end_buffer := pdb_buffer[size_of(PDB_MSF_Header):][:directory_block_count * size_of(u32)]
	directory_block_offsets := slice.reinterpret([]u32, msf_end_buffer)
	directory_offsets := slice.reinterpret([]u32, linearize_stream(pdb_buffer, directory_block_offsets, msf_hdr.block_size, directory_block_count * size_of(u32)))
	directory_stream  := slice.reinterpret([]u32, linearize_stream(pdb_buffer, directory_offsets, msf_hdr.block_size, msf_hdr.directory_size))

	stream_count  := directory_stream[0]
	stream_sizes  := directory_stream[1:1+stream_count]
	stream_blocks := directory_stream[1+stream_count:]
	
	// This is the offset into the stream directory. Each one points to the list of blocks that make up a stream
	stream_block_offsets := make([]u32, stream_count)
	offset_into_stream_blocks : u32 = 0
	for i := 0; i < len(stream_sizes); i += 1 {
		stream_block_count := div_ceil(stream_sizes[i], msf_hdr.block_size)
		stream_block_offsets[i] = offset_into_stream_blocks
		offset_into_stream_blocks += stream_block_count
	}

	dbi_offset_stream_offset := stream_block_offsets[DBI_STREAM_IDX]
	dbi_stream_size := stream_sizes[DBI_STREAM_IDX]
	dbi_offset_stream := stream_blocks[dbi_offset_stream_offset:]
	dbi_stream := linearize_stream(pdb_buffer, dbi_offset_stream, msf_hdr.block_size, dbi_stream_size)

	dbi_hdr := slice_to_type(dbi_stream, PDB_DBI_Header) or_return
	if dbi_hdr.version != PDB_V70 {
		return false
	}

	skew_size : u64 = 0
	symbol_found := false

	mod_offset := size_of(PDB_DBI_Header)
	last_mod_info := int(dbi_hdr.mod_info_size) + size_of(PDB_DBI_Header)
	first_pass: for ; mod_offset < last_mod_info; {
		mod_info_hdr := slice_to_type(dbi_stream[mod_offset:], PDB_Module_Info) or_return
		mod_offset += size_of(PDB_Module_Info)

		module_name := cstring(raw_data(dbi_stream[mod_offset:]))
		mod_name_sz := len(module_name) + 1
		mod_offset += mod_name_sz

		object_name := cstring(raw_data(dbi_stream[mod_offset:]))
		obj_name_sz := len(object_name) + 1
		mod_offset += obj_name_sz

		mod_offset = i_round_up(mod_offset, 4)

		// Skip over modules with no symbols
		if mod_info_hdr.module_symbol_stream == max(u16) {
			continue
		}

		symbol_offset_stream_offset := stream_block_offsets[mod_info_hdr.module_symbol_stream]
		symbol_stream_size := stream_sizes[mod_info_hdr.module_symbol_stream]
		symbol_offset_stream := stream_blocks[symbol_offset_stream_offset:]

		symbol_stream := linearize_stream(pdb_buffer, symbol_offset_stream, msf_hdr.block_size, symbol_stream_size)
		defer delete(symbol_stream)

		// skipping over codeview signature
		sym_offset := 4
		for ; sym_offset < (int(mod_info_hdr.symbols_size) - 2); {
			sym_hdr := slice_to_type(symbol_stream[sym_offset:], PDB_Symbol_Header) or_return
			#partial switch sym_hdr.type {
				case .GlobalProc32: fallthrough
				case .LocalProc32: {
					proc_symbol := slice_to_type(symbol_stream[sym_offset:], CV_Proc32) or_return
					symbol_name := string(cstring(raw_data(symbol_stream[sym_offset+size_of(CV_Proc32):])))

					section_offset := proc_symbol.section_idx * size_of(COFF_Section_Header)
					section_hdr := slice_to_type(section_buffer[section_offset:], COFF_Section_Header) or_return

					symbol_addr := u64(section_hdr.virtual_addr + proc_symbol.offset)
					interned_symbol := in_get(&trace.intern, &trace.string_block, symbol_name)
					am_insert(&trace.addr_map, symbol_addr, interned_symbol)

					if !symbol_found && symbol_name == "spall_auto_init" {
						skew_size = trace.skew_address - symbol_addr
						symbol_found = true
					}
				}
			}

			sym_offset += 2 + int(sym_hdr.length)
		}
	}

	am_skew(&trace.addr_map, skew_size)
	return true
}

linearize_stream :: proc(data: []u8, indices: []u32, block_size: u32, stream_size: u32) -> []u8 {
	block_count := div_ceil(stream_size, block_size)
	linear_space := make([]u8, block_count * block_size)

	full_block_count, leftovers := math.divmod(stream_size, block_size)

	copy_offset : u32 = 0
	for i : u32 = 0; i < full_block_count; i += 1 {
		data_offset := indices[i] * block_size
		mem.copy(raw_data(linear_space[copy_offset:]), raw_data(data[data_offset:]), int(block_size))
		copy_offset += block_size
	}

	if leftovers > 0 {
		data_offset := indices[block_count - 1] * block_size
		mem.copy(raw_data(linear_space[copy_offset:]), raw_data(data[data_offset:]), int(leftovers))
	}

	return linear_space
}
