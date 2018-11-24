#include "compression.h"

#define CHUNK_SIZE 16384

namespace REDasm {

bool Compression::deflate(Buffer &buffin, Buffer &buffout)
{
    if(buffin.empty())
        return false;

    z_stream zs;
    Compression::prepare(&zs, buffin, buffout);

    if(deflateInit(&zs, Z_BEST_COMPRESSION) != Z_OK)
        return false;

    bool res = Compression::process(&zs, buffout, ::deflate, Z_FINISH);
    deflateEnd(&zs);
    return res;
}

bool Compression::inflate(Buffer &buffin, Buffer &buffout)
{
    if(buffin.empty())
        return false;

    z_stream zs;
    Compression::prepare(&zs, buffin, buffout);

    if(inflateInit(&zs) != Z_OK)
        return false;

    bool res = Compression::process(&zs, buffout, ::inflate, 0);
    inflateEnd(&zs);
    return res;
}

void Compression::prepare(z_stream *zs, Buffer& buffin, Buffer& buffout)
{
    buffout.resize(CHUNK_SIZE);

    zs->zalloc = Z_NULL;
    zs->zfree = Z_NULL;
    zs->opaque = Z_NULL;

    zs->next_in = reinterpret_cast<Bytef*>(buffin.data());
    zs->avail_in = static_cast<uInt>(buffin.size());

    zs->total_out = 0;
}

bool Compression::process(z_stream *zs, Buffer &buffout, const Compression::ZLibFunction &func, int funcarg)
{
    int res = 0;

    do
    {
        if(zs->total_out >= static_cast<uLong>(buffout.size()))
            buffout.resize(buffout.size() * 2);

        zs->next_out = reinterpret_cast<Bytef*>(buffout.data() + zs->total_out);
        zs->avail_out = static_cast<uInt>(buffout.size() - zs->total_out);
        res = func(zs, funcarg);

        if(res == Z_STREAM_END)
            break;

        if(res != Z_OK)
            buffout.clear();
    }
    while(res == Z_OK);

    if(buffout.size() > zs->total_out)
        buffout.resize(zs->total_out);

    return res == Z_STREAM_END;
}

} // namespace REDasm
