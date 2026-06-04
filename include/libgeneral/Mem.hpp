#pragma once
#include <vector>
#include <cstdint>
#include <cstring>
#include <string>

namespace tihmstar {
    class Mem {
    public:
        Mem() = default;
        Mem(const void *data, size_t len){ append(data,len); }
        Mem(const std::string &s){ append(s.data(), s.size()); }
        void append(const void *data, size_t len){
            if(!data || len==0) return;
            const uint8_t *d = (const uint8_t*)data;
            _buf.insert(_buf.end(), d, d+len);
        }
        size_t size() const { return _buf.size(); }
        const uint8_t* data() const { return _buf.empty()? nullptr: &_buf[0]; }
        const void* buf() const { return data(); }
        void clear(){ _buf.clear(); }
        std::string str() const { return std::string((const char*)data(), size()); }
    private:
        std::vector<uint8_t> _buf;
    };
}
