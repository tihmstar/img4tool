#pragma once
#include <string>
#include <vector>
#include <cstdio>
#include <sys/stat.h>
#include "Mem.hpp"

namespace tihmstar {
    inline Mem readFile(const char *path){
        FILE *f = fopen(path, "rb");
        if(!f) throw exception("readFile failed");
        struct stat st;
        if(fstat(fileno(f), &st) != 0){ fclose(f); throw exception("fstat failed"); }
        size_t size = st.st_size;
        Mem ret;
        if(size){
            std::vector<char> buf(size);
            if(fread(buf.data(), 1, size, f) != size){ fclose(f); throw exception("readFile failed to read"); }
            ret.append(buf.data(), size);
        }
        fclose(f);
        return ret;
    }
}
