package main

import "core:strings"
import "core:fmt"
import "core:math"

import SDL "vendor:sdl2"
import SDL_TTF "vendor:sdl2/ttf"
import gl "vendor:OpenGL"

draw_rect :: proc(rects: ^[dynamic]DrawRect, rect: Rect, color: BVec4) {
	append(rects, DrawRect{FVec4{f32(rect.pos.x), f32(rect.pos.y), f32(rect.size.x), f32(rect.size.y)}, color, FVec2{-2, 0.0}})
}

draw_line :: proc(rects: ^[dynamic]DrawRect, start, end: Vec2, width: f64, color: BVec4) {
	start, end := start, end
	if start.x > end.x {
		end, start = start, end
	}

	append(rects, DrawRect{FVec4{f32(start.x), f32(start.y), f32(end.x), f32(end.y)}, color, FVec2{f32(width), -2}})
}

draw_rect_outline :: proc(rects: ^[dynamic]DrawRect, rect: Rect, width: f64, color: BVec4) {
	x1 := rect.pos.x
	y1 := rect.pos.y
	x2 := rect.pos.x + rect.size.x
	y2 := rect.pos.y + rect.size.y

	draw_line(rects, Vec2{x1, y1}, Vec2{x2, y1}, width, color)
	draw_line(rects, Vec2{x1, y1}, Vec2{x1, y2}, width, color)
	draw_line(rects, Vec2{x2, y1}, Vec2{x2, y2}, width, color)
	draw_line(rects, Vec2{x1, y2}, Vec2{x2, y2}, width, color)
}

draw_rect_inline :: proc(rects: ^[dynamic]DrawRect, rect: Rect, width: f64, color: BVec4) {
	x1 := rect.pos.x + width
	y1 := rect.pos.y + width
	x2 := rect.pos.x + rect.size.x - width
	y2 := rect.pos.y + rect.size.y - width

	draw_line(rects, Vec2{x1, y1}, Vec2{x2, y1}, width, color)
	draw_line(rects, Vec2{x1, y1}, Vec2{x1, y2}, width, color)
	draw_line(rects, Vec2{x2, y1}, Vec2{x2, y2}, width, color)
	draw_line(rects, Vec2{x1, y2}, Vec2{x2, y2}, width, color)
}

set_cursor :: proc(type: string) {
	switch type {
	case "auto": SDL.SetCursor(default_cursor)
	case "pointer": SDL.SetCursor(pointer_cursor)
	}
	is_hovering = true
}
reset_cursor :: proc() { 
	set_cursor("auto") 
	is_hovering = false
}

get_font :: proc(scale: FontSize, font_type: FontType) -> ^SDL_TTF.Font {
	font_idx := (u32(font_type) * u32(FontSize.LastSize)) + u32(scale)
	return all_fonts[font_idx]
}

get_text_height :: proc(scale: FontSize, font: FontType) -> f64 { 
	#partial switch scale {
	case .PSize: return p_height
	case .H1Size: return h1_height
	case .H2Size: return h2_height
	}

	push_fatal(SpallError.Bug)
}
measure_text :: proc(str: string, scale: FontSize, font_type: FontType) -> f64 {
	if len(str) == 0 {
		return 0
	}

	font := get_font(scale, font_type)
	potato := strings.clone_to_cstring(str, context.temp_allocator)

	width: i32
	height: i32
	SDL_TTF.SizeUTF8(font, potato, &width, &height)

	return f64(width)
}
draw_text    :: proc(rects: ^[dynamic]DrawRect, str: string, pos: Vec2, scale: FontSize, font_type: FontType, color: BVec4) {
	if len(str) == 0 {
		return
	}

	font := get_font(scale, font_type)
	potato := strings.clone_to_cstring(str, context.temp_allocator)

	surface := SDL_TTF.RenderUTF8_Blended(font, potato, SDL.Color{color.x, color.y, color.z, color.w})


	pixels := make([]u8, surface.w * surface.h * 4)
	SDL.ConvertPixels(surface.w, surface.h, surface.format.format, surface.pixels, surface.pitch,
	                  surface.format.format, raw_data(pixels), surface.w * 4);

	texture_handle : u32 = 0
	gl.GenTextures(1, &texture_handle);
	gl.ActiveTexture(gl.TEXTURE0);
	gl.BindTexture(gl.TEXTURE_2D, texture_handle);
	gl.TexParameteri(gl.TEXTURE_2D, gl.TEXTURE_MIN_FILTER, gl.LINEAR);
	gl.TexParameteri(gl.TEXTURE_2D, gl.TEXTURE_MAG_FILTER, gl.LINEAR);
	gl.TexParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_S, gl.CLAMP_TO_EDGE);
	gl.TexParameteri(gl.TEXTURE_2D, gl.TEXTURE_WRAP_T, gl.CLAMP_TO_EDGE);
	gl.TexImage2D(gl.TEXTURE_2D, 0, gl.RGBA, surface.w, surface.h, 0, gl.RGBA, gl.UNSIGNED_BYTE, raw_data(pixels));

	delete(pixels)
	SDL.FreeSurface(surface);

	x_pos := i32(math.round(pos.x))
	y_pos := i32(math.round(pos.y))
	append(rects, DrawRect{FVec4{f32(x_pos), f32(y_pos), f32(surface.w), f32(surface.h)}, color, FVec2{0.0, 0.0}})
	
	// flush. RIP
	gl.BufferData(gl.ARRAY_BUFFER, len(rects)*size_of(rects[0]), raw_data(rects[:]), gl.DYNAMIC_DRAW)
	gl.DrawElementsInstanced(gl.TRIANGLES, i32(len(indices)), gl.UNSIGNED_SHORT, nil, i32(len(rects)))
	resize(rects, 0)

	gl.DeleteTextures(1, &texture_handle);
}

open_file_dialog :: proc() {}
get_system_color :: proc() -> bool { return false }
get_session_storage :: proc(key: string) { }
set_session_storage :: proc(key, val: string) { }
