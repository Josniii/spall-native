clang -o same -g main.c
clang -dynamiclib -o same.dylib -g dylib_shim.c
