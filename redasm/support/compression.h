#ifndef COMPRESSION_H
#define COMPRESSION_H

#include "../redasm_buffer.h"
#include <functional>
#include <zlib.h>

namespace REDasm {

class Compression
{
    private:
        typedef std::function<int(z_stream*, int)> ZLibFunction;

    public:
        Compression() = delete;
        Compression(const Compression&) = delete;
        Compression& operator =(const Compression&) = delete;

    public:
        static bool deflate(Buffer &buffin, Buffer& buffout);
        static bool inflate(Buffer &buffin, Buffer& buffout);

    private:
        static void prepare(z_stream* zs, Buffer &buffin, Buffer &buffout);
        static bool process(z_stream* zs, Buffer &buffout, const ZLibFunction& func, int funcarg);
};

} // namespace REDasm

#endif // COMPRESSION_H
