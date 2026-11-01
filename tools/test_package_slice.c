#include "slice.h"
#include <assert.h>
#include <unistd.h>
int main(int argc, char **argv) {
    assert(argc == 2);
    FILE *f = package_open(argv[1], "rb"); assert(f);
    char b[8] = {0};
    assert(fread(b, 1, sizeof b, f) == 3 && b[0] == 'a' && b[2] == 'c');
    assert(fseeko(f, -2, SEEK_END) == 0 && fgetc(f) == 'b');
    assert(fseeko(f, 4, SEEK_SET) != 0);
    fclose(f);
    return 0;
}
