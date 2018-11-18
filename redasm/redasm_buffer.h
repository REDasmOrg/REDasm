#ifndef REDASM_BUFFER_H
#define REDASM_BUFFER_H

#include <string>
#include <vector>
#include "redasm_types.h"
#include "redasm_endianness.h"

namespace REDasm {

class BufferRef;

class Buffer: public std::vector<u8>
{
    friend class BufferRef;

    public:
        Buffer();
        BufferRef slice(u64 offset);
        Buffer createFilled(size_t n, u8 b = 0) const;
        void endianness(endianness_t e);

    public:
        static Buffer fromFile(const std::string& file);
        static Buffer fill(size_t count, u8 b = 0);
        u8 operator *() const { return this->at(0); }

    public:
        template<typename T> operator T() const;
        template<typename T> operator T*() const { return reinterpret_cast<T*>(this->data()); }

    private:
        endianness_t m_endianness;

    public:
        static Buffer invalid;
};

template<typename T> Buffer::operator T() const
{
    T val = *reinterpret_cast<T*>(this->data());

    if(m_endianness == Endianness::BigEndian)
        return Endianness::cfbe<T>(val);

    return Endianness::cfle<T>(val);
}

class BufferRef
{
    public:
        BufferRef();
        BufferRef(Buffer* buffer, u64 offset);
        BufferRef(BufferRef* buffer, u64 offset);
        BufferRef& advance(int offset);
        Buffer filled(size_t n, u8 b = 0) const;
        bool copyTo(Buffer& buffer);
        bool eob() const;
        bool empty() const;
        size_t size() const;
        u8* data() const;
        u8* data();

    public:
        u8 operator [](size_t idx) const;
        u8 operator *() const { return *m_data; }
        BufferRef operator ++(int) { BufferRef copy(this, 0); this->m_data++; this->m_size--; return copy; }
        BufferRef& operator ++() { this->m_data++; this->m_size--; return *this; }

    public:
        template<typename T> BufferRef& operator =(T rhs);
        template<typename T> operator T() const;
        template<typename T> operator T*() const { return reinterpret_cast<T*>(this->data()); }

    private:
        Buffer* m_buffer;
        u8* m_data;
        size_t m_size;
};

template<typename T> BufferRef& BufferRef::operator =(T rhs)
{
    T* p = reinterpret_cast<T*>(m_data);

    if(Endianness::current() == Endianness::BigEndian)
        *p = Endianness::cfbe<T>(rhs);
    else
        *p = Endianness::cfle<T>(rhs);

    return *this;
}

template<typename T> BufferRef::operator T() const
{
    T val = *reinterpret_cast<T*>(m_data);

    if(m_buffer->m_endianness == Endianness::BigEndian)
        return Endianness::cfbe<T>(val);

    return Endianness::cfle<T>(val);
}

} // namespace REDasm

#endif // REDASM_BUFFER_H
