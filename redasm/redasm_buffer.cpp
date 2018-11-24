#include "redasm_buffer.h"
#include <stdexcept>
#include <fstream>

namespace REDasm {

Buffer Buffer::invalid;

Buffer::Buffer(): std::vector<u8>(), m_endianness(Endianness::current()) { }
BufferRef Buffer::slice(u64 offset) { return BufferRef(this, offset); }

Buffer Buffer::createFilled(size_t n, u8 b) const
{
    Buffer buffer;
    buffer.endianness(m_endianness);
    buffer.resize(n, b);
    return buffer;
}

void Buffer::endianness(endianness_t e) { m_endianness = e; }

Buffer Buffer::fromFile(const std::string &file)
{
    std::ifstream ifs(file, std::ios::in | std::ios::ate);

    if(!ifs.is_open())
        return Buffer();

    size_t size = ifs.tellg();

    if(!size)
        return Buffer();

    ifs.seekg(0, std::ios::beg);

    Buffer b;
    b.resize(size);

    ifs.read(reinterpret_cast<char*>(b.data()), size);
    ifs.close();

    return b;
}

Buffer Buffer::fill(size_t count, u8 b)
{
    Buffer buffer;
    buffer.resize(count, b);
    return buffer;
}

BufferRef::BufferRef(): m_buffer(NULL), m_data(NULL), m_size(0) { }

BufferRef::BufferRef(Buffer *buffer, u64 offset): m_buffer(buffer)
{
    if(offset >= buffer->size())
    {
        m_data = NULL;
        m_size = 0;
        return;
    }

    m_data = buffer->data() + offset;
    m_size = buffer->size() - offset;
}

BufferRef::BufferRef(BufferRef *buffer, u64 offset): m_buffer(buffer->m_buffer)
{
    if(offset >= buffer->size())
    {
        m_data = NULL;
        m_size = 0;
        return;
    }

    m_data = buffer->data() + offset;
    m_size = buffer->size() - offset;
}

BufferRef &BufferRef::advance(int offset)
{
    m_data += offset;
    m_size -= offset;
    return *this;
}

Buffer BufferRef::filled(size_t n, u8 b) const { return m_buffer->createFilled(n, b); }

bool BufferRef::copyTo(Buffer &buffer)
{
    if(this->empty())
        return false;

    buffer.resize(m_size);
    std::ptrdiff_t offset = m_data - m_buffer->data();

    if(offset < 0)
        return false;

    std::copy(m_buffer->begin() + offset, m_buffer->end(), buffer.begin());
    return true;
}

bool BufferRef::eob() const { return !m_data || !m_size || (m_size >= m_buffer->size()); }
bool BufferRef::empty() const { return !m_data || !m_size; }
size_t BufferRef::size() const { return m_size; }
u8 *BufferRef::data() const { return const_cast<BufferRef*>(this)->data(); }
u8 *BufferRef::data() { return m_data; }

u8 BufferRef::operator[](size_t idx) const
{
    if(idx >= m_size)
        throw std::range_error("BufferRef: Index out of bounds");

    return m_data[idx];
}

} // namespace REDasm
