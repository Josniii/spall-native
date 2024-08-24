#include <stdio.h>

__attribute__((constructor))
static void load_same(int argc, const char **argv) {
	printf("Hello from dylib!\n");
}
