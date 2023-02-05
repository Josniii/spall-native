package main

MACH_MAGIC_64 :: 0xfeedfacf

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
		symbol_name := string(cstring(raw_data(string_table_bytes[symbol.string_table_idx:])))

		if symbol_name == "_spall_auto_init" {
			skew_size = trace.skew_address - u64(symbol.value)
			break
		}
	}

	for i := 0; i < int(symtab_header.symbol_count); i += 1 {
		symbol_buffer := exec_buffer[int(symtab_header.symbol_table_offset)+(i * size_of(Mach_Symbol_Entry_64)):]
		symbol := (^Mach_Symbol_Entry_64)(raw_data(symbol_buffer[:size_of(Mach_Symbol_Entry_64)]))
		symbol_name := string(cstring(raw_data(string_table_bytes[symbol.string_table_idx:])))

		if symbol.value != 0 {
			interned_symbol := in_get(&trace.intern, &trace.string_block, symbol_name)

			symbol_addr := symbol.value + skew_size
			am_insert(&trace.addr_map, symbol_addr, interned_symbol)
		}
	}

	return true
}
