#ifndef REDASM_H
#define REDASM_H

#include <memory>
#include <functional>
#include <unordered_map>
#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>
#include <list>
#include <map>
#include <set>
#include "support/utils.h"

typedef uint8_t u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int8_t  s8;
typedef int16_t s16;
typedef int32_t s32;
typedef int64_t s64;

typedef s64 register_t;
typedef u64 address_t;
typedef u64 offset_t;

#define RE_UNUSED(x)           (void)x
#define ENTRYPOINT_FUNCTION    "entrypoint"
#define REGISTER_INVALID       static_cast<s64>(-1)

namespace REDasm {

namespace ByteOrder {
    enum { LittleEndian = 0, BigEndian = 1, };

    /*
    static int current()
    {
        int i = 1;
        char* p = reinterpret_cast<char*>(&i);

        if (p[0] == 1)
            return ByteOrder::LittleEndian;

        return ByteOrder::BigEndian;
    }
    */
}

namespace SegmentTypes {
    enum: u32 {
        None       = 0x00000000,

        Code       = 0x00000001,
        Data       = 0x00000002,

        Read       = 0x00000010,
        Write      = 0x00000020,
        Bss        = 0x00000040,
    };
}

namespace InstructionTypes {
    enum: u32 {
        None        = 0x00000000, Stop = 0x00000001, Nop = 0x00000002,
        Jump        = 0x00000004, Call = 0x00000008,
        Add         = 0x00000010, Sub  = 0x00000020, Mul = 0x00000040, Div = 0x0000080, Mod = 0x00000100,
        And         = 0x00000200, Or   = 0x00000400, Xor = 0x00000800, Not = 0x0001000,
        Push        = 0x00002000, Pop  = 0x00004000,
        Compare     = 0x00008000,

        Conditional = 0x01000000, Privileged = 0x02000000, JumpTable = 0x04000000 | Jump,
        Invalid     = 0x10000000,
        Branch      = Jump | Call,
    };
}

namespace OperandTypes {
    enum: u32 {
        None         = 0x00000000,
        Register     = 0x00000001,  // Register
        Immediate    = 0x00000002,  // Immediate Value
        Memory       = 0x00000004,  // Direct Memory Pointer
        Displacement = 0x00000008,  // Indirect Memory Pointer

        Local        = 0x00010000,  // Local Variable
        Argument     = 0x00020000,  // Function Argument
        Read         = 0x00100000,  // Read from...
        Write        = 0x00200000,  // Write to...
    };
}

namespace BlockInfo {
    enum: u32 {
        None        = 0x00000000,
        BlockStart  = 0x00000001,
        BlockEnd    = 0x00000002,
        GraphStart  = 0x00000004,
        GraphEnd    = 0x00000008,

        Ignore      = 0x10000000,
    };
}

struct Buffer
{
    Buffer(): data(NULL), length(0) { }
    Buffer(u8* data, u64 length): data(data), length(length) { }
    Buffer(char* data, u64 length): data(reinterpret_cast<u8*>(data)), length(length) { }
    Buffer operator +(u64 v) const { Buffer b(data, length); b.data += v; b.length -= v; return b; }
    Buffer& operator +=(u64 v) { data += v; length -= v; return *this; }
    Buffer& operator++(int) { *this += 1; return *this; }
    u8 operator[](int index) const { return data[index]; }
    u8 operator*() const { return *data; }
    bool eob() const { return !length; }

    u8* data;
    u64 length;
};

struct Signature
{
    std::string name, pattern;
    u8 alen;
    u16 asum;
};

struct Segment
{
    Segment(): offset(0), address(0), endaddress(0), type(0) { }
    Segment(const std::string& name, offset_t offset, address_t address, u64 size, u64 flags): name(name), offset(offset), address(address), endaddress(address + size), type(flags) { }

    u64 size() const { return endaddress - address; }
    bool contains(address_t address) const { return (address >= this->address) && (address < endaddress); }
    bool is(u32 t) const { return type & t; }

    std::string name;
    offset_t offset;
    address_t address, endaddress;
    u32 type;
};

struct RegisterOperand
{
    RegisterOperand(): type(0), r(REGISTER_INVALID) { }
    RegisterOperand(u32 type, register_t r): type(type), r(r) { }
    RegisterOperand(register_t r): type(0), r(r) { }

    u32 type;
    register_t r;

    bool isValid() const { return r != REGISTER_INVALID; }
};

struct MemoryOperand
{
    MemoryOperand(): scale(1), displacement(0) { }
    MemoryOperand(const RegisterOperand& base, const RegisterOperand& index, s32 scale, s64 displacement): base(base), index(index), scale(scale), displacement(displacement) { }

    RegisterOperand base, index;
    s32 scale;
    s64 displacement;

    bool displacementOnly() const { return !base.isValid() && !index.isValid(); }
};

struct Operand
{
    Operand(): loc_index(-1), type(OperandTypes::None), index(-1), u_value(0) { }
    Operand(u32 type, s32 value, s32 pos): loc_index(-1), type(type), index(pos), s_value(value) { }
    Operand(u32 type, u32 value, s32 pos): loc_index(-1), type(type), index(pos), u_value(value) { }
    Operand(u32 type, s64 value, s32 pos): loc_index(-1), type(type), index(pos), s_value(value) { }
    Operand(u32 type, u64 value, s32 pos): loc_index(-1), type(type), index(pos), u_value(value) { }

    s64 loc_index;
    u32 type;
    s32 index;
    RegisterOperand reg;
    MemoryOperand mem;

    union {
        s64 s_value;
        u64 u_value;
    };

    void r() { type |= OperandTypes::Read;  }
    void w() { type |= OperandTypes::Write; }
    bool is(u32 t) const { return type & t; }
    bool isRead() const  { return this->is(OperandTypes::Read);  }
    bool isWrite() const { return this->is(OperandTypes::Write); }
};

struct Instruction
{
    Instruction(): address(0), target_idx(-1), type(0), size(0), blockinfo(0), id(0), userdata(NULL) { }
    ~Instruction() { reset(); }

    std::function<void(void*)> free;

    std::string mnemonic, signature;
    std::list<address_t> targets;   // Jump/JumpTable/Call destination(s)
    std::vector<Operand> operands;
    std::list<std::string> comments;
    address_t address;
    s32 target_idx;                 // Target's operand index
    u32 type, size, blockinfo;
    u64 id;                         // Backend Specific
    void* userdata;                 // It doesn't survive after Processor::decode() by design

    bool is(u32 t) const { return type & t; }
    bool blockIs(u32 t) const { return blockinfo & t; }
    bool isInvalid() const { return type == InstructionTypes::Invalid; }
    bool hasTargets() const { return !targets.empty(); }
    void reset() { type = 0; operands.clear(); if(free && userdata) { free(userdata); userdata = NULL; } }
    void target_op(s32 index) { target_idx = index; targets.push_back(operands[index].u_value); }
    void target(address_t target) { targets.push_back(target); }
    address_t target() const { return targets.front(); }
    address_t endAddress() const { return address + size; }

    Instruction& cmt(const std::string& s) { comments.push_back(s); return *this; }
    Instruction& op(Operand op) { op.index = operands.size(); operands.push_back(op); return *this; }
    Instruction& mem(address_t v) { operands.push_back(Operand(OperandTypes::Memory, v, operands.size())); return *this; }
    template<typename T> Instruction& imm(T v) { operands.push_back(Operand(OperandTypes::Immediate, v, operands.size())); return *this; }
    template<typename T> Instruction& disp(register_t base, T displacement) { return disp(base, REGISTER_INVALID, displacement); }
    template<typename T> Instruction& disp(register_t base, register_t index, T displacement) { return disp(base, index, 1, displacement); }
    template<typename T> Instruction& disp(register_t base, register_t index, s32 scale, T displacement);
    template<typename T> Instruction& arg(s32 index, register_t base, T displacement) { return local(index, base, displacement, OperandTypes::Argument); }
    template<typename T> Instruction& local(s32 index, register_t base, T displacement, u32 type = OperandTypes::Local);

    Instruction& reg(register_t r, u64 type = 0)
    {
        Operand op;
        op.index = operands.size();
        op.type = OperandTypes::Register;
        op.reg = RegisterOperand(type, r);

        operands.push_back(op);
        return *this;
    }
};

template<typename T> Instruction& Instruction::disp(register_t base, register_t index, s32 scale, T displacement)
{
    Operand op;
    op.index = operands.size();
    op.type = OperandTypes::Displacement;
    op.mem = MemoryOperand(RegisterOperand(base), RegisterOperand(index), scale, displacement);

    operands.push_back(op);
    return *this;
}

template<typename T> Instruction& Instruction::local(s32 index, register_t base, T displacement, u32 type)
{
    Operand op;
    op.index = operands.size();
    op.loc_index = index;
    op.type = OperandTypes::Displacement | type;
    op.mem = MemoryOperand(RegisterOperand(base), RegisterOperand(index), 1, displacement);

    operands.push_back(op);
    return *this;
}

typedef std::shared_ptr<Instruction> InstructionPtr;
typedef std::vector<Operand> OperandList;
typedef std::vector<address_t> AddressList;
typedef std::vector<Segment> SegmentList;
typedef std::vector<Signature> SignatureList;
typedef std::list<std::string> SignatureFiles;

} // namespace REDasm

#endif // REDASM_H
