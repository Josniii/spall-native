package main

import "core:fmt"
import "core:os"
import "core:bytes"

MACH_CMD_SYMTAB :: 2
Mach_Header_64 :: struct #packed {
	magic:       u32,
	cpu_type:    u32,
	cpu_subtype: u32,
	file_type:   u32,
	cmd_count:   u32,
	cmd_size:    u32,
	flags:       u32,
	reserved:    u32,
}

Mach_Load_Command :: struct #packed {
	type: u32,
	size: u32,
}

Mach_Symtab_Command :: struct #packed {
	type:                u32,
	size:                u32,
	symbol_table_offset: u32,
	symbol_count:        u32,
	string_table_offset: u32,
	string_table_size:   u32,
}

Mach_Symbol_Entry_64 :: struct #packed {
	string_table_idx: u32,
	type: u8,
	section_count: u8,
	description: u16,
	value: u64,
}

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

ELF_MAGIC     := []u8{ 0x7f, 'E', 'L', 'F' }
MACH_MAGIC_64 :: 0xfeedfacf
DOS_MAGIC     := []u8{ 0x4d, 0x5a }
PE32_MAGIC    := []u8{ 'P', 'E', 0, 0 }

load_executable :: proc(trace: ^Trace, file_name: string) -> bool {
	fmt.printf("Loading symbols from %s\n", file_name)

	exec_buffer, ok := os.read_entire_file_from_filename(file_name)
	if !ok {
		post_error(trace, "Failed to load %s!", file_name)
		return false
	}
	if len(exec_buffer) < 4 {
		post_error(trace, "Invalid executable file!")
		return false
	}

	magic_chunk := (^u32)(raw_data(exec_buffer[:4]))^
	if bytes.equal(exec_buffer[:4], ELF_MAGIC) {
		ok := load_elf(trace, exec_buffer)
		if !ok {
			post_error(trace, "Failed to parse ELF!")
			return false
		}
	} else if magic_chunk == MACH_MAGIC_64 {
		ok := load_macho(trace, exec_buffer)
		if !ok {
			post_error(trace, "Failed to parse Mach-O!")
			return false
		}
	} else if bytes.equal(exec_buffer[:2], DOS_MAGIC) {
		ok := load_pe32(trace, exec_buffer)
		if !ok {
			post_error(trace, "Failed to parse PE32!")
			return false
		}
	} else {
		post_error(trace, "Unsupported executable type! %x", exec_buffer[:4])
		return false
	}

	fmt.printf("Loaded %d symbols!\n", len(trace.addr_map.entries))

	return true
}

load_macho :: proc(trace: ^Trace, exec_buffer: []u8) -> bool {
	if len(exec_buffer) < size_of(Mach_Header_64) {
		return false
	}

	header := (^Mach_Header_64)(raw_data(exec_buffer[:size_of(Mach_Header_64)]))
	if header.file_type != 2 {
		return false
	}

	symtab_header := Mach_Symtab_Command{}

	read_idx := size_of(Mach_Header_64)
	for read_idx < len(exec_buffer) {
		current_buffer := exec_buffer[read_idx:]
		cmd := (^Mach_Load_Command)(raw_data(current_buffer[:size_of(Mach_Load_Command)]))
		if cmd.size == 0 {
			return false
		}

		if cmd.type == MACH_CMD_SYMTAB {
			symtab_header = (^Mach_Symtab_Command)(raw_data(current_buffer[:size_of(Mach_Symtab_Command)]))^
			break
		} 

		read_idx += int(cmd.size)
	}
	if read_idx >= len(exec_buffer) {
		return false
	}
	
	symbol_table_size := symtab_header.symbol_count * size_of(Mach_Symbol_Entry_64)
	if len(exec_buffer) < int(symtab_header.symbol_table_offset + symbol_table_size) ||
	   len(exec_buffer) < int(symtab_header.string_table_offset + symtab_header.string_table_size) {
		return false
	}

	skew_size : u64 = 0
	symbol_table_bytes := exec_buffer[symtab_header.symbol_table_offset:]
	string_table_bytes := exec_buffer[symtab_header.string_table_offset:]
	for i := 0; i < int(symtab_header.symbol_count); i += 1 {
		symbol_buffer := exec_buffer[int(symtab_header.symbol_table_offset)+(i * size_of(Mach_Symbol_Entry_64)):]
		symbol := (^Mach_Symbol_Entry_64)(raw_data(symbol_buffer[:size_of(Mach_Symbol_Entry_64)]))
		symbol_name := string(transmute(cstring)raw_data(string_table_bytes[symbol.string_table_idx:]))

		if symbol_name == "_spall_auto_init" {
			skew_size = trace.skew_address - u64(symbol.value)
			break
		}
	}

	for i := 0; i < int(symtab_header.symbol_count); i += 1 {
		symbol_buffer := exec_buffer[int(symtab_header.symbol_table_offset)+(i * size_of(Mach_Symbol_Entry_64)):]
		symbol := (^Mach_Symbol_Entry_64)(raw_data(symbol_buffer[:size_of(Mach_Symbol_Entry_64)]))
		symbol_name := string(transmute(cstring)raw_data(string_table_bytes[symbol.string_table_idx:]))

		if symbol.value != 0 {
			interned_symbol := in_get(&trace.intern, &trace.string_block, symbol_name)

			symbol_addr := symbol.value + skew_size
			am_insert(&trace.addr_map, symbol_addr, interned_symbol)
		}
	}

	return true
}

load_pe32 :: proc(trace: ^Trace, exec_buffer: []u8) -> bool {
	dos_end_offset := 0x3c
	pe_hdr_offset := (^u32)(raw_data(exec_buffer[dos_end_offset:dos_end_offset+4]))^

	cur_offset := int(pe_hdr_offset)
	pe_hdr := (^PE32_Header)(raw_data(exec_buffer[cur_offset:cur_offset+size_of(PE32_Header)]))

	if !bytes.equal(pe_hdr.magic[:], PE32_MAGIC) {
		return false
	}

	cur_offset += size_of(PE32_Header)
	section_bytes := (size_of(COFF_Section_Header) * int(pe_hdr.coff_header.section_count))

	pdb_path : cstring = ""
	// 6 is always debug
	debug_rva := pe_hdr.optional_header.data_directories[6].virtual_addr
	for i := 0; i < int(pe_hdr.coff_header.section_count); i += 1 {
		section_offset := i * size_of(COFF_Section_Header)
		section_hdr := (^COFF_Section_Header)(raw_data(exec_buffer[cur_offset+section_offset:cur_offset+section_offset+size_of(COFF_Section_Header)]))

		start := section_hdr.virtual_addr
		end   := start + section_hdr.virtual_size
		if debug_rva < start || (debug_rva + size_of(COFF_Debug_Directory)) > end {
			continue
		}

		section_relative_offset := debug_rva - start
		dir_offset := section_hdr.raw_data_offset + section_relative_offset
		debug_dir := (^COFF_Debug_Directory)(raw_data(exec_buffer[dir_offset:dir_offset+size_of(COFF_Debug_Directory)]))
		if debug_dir.type != DEBUG_TYPE_CODEVIEW {
			break
		}

		if debug_dir.data_size <= size_of(COFF_Debug_Entry) {
			break
		}

		pdb_path = cstring(raw_data(exec_buffer[debug_dir.raw_data_offset+size_of(COFF_Debug_Entry):]))
		break
	}
	if pdb_path == "" {
		return false
	}

	fmt.printf("PDB is at %s\n", pdb_path)

	return false
}

// ELF is in another castle
