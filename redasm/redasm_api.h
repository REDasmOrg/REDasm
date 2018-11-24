#ifndef REDASM_API_H
#define REDASM_API_H

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
#include "redasm_runtime.h"
#include "redasm_buffer.h"
#include "redasm_types.h"

#if __cplusplus <= 201103L && __GNUC__
namespace std {
template<typename T, typename... Args> std::unique_ptr<T> make_unique(Args&&... args) { return std::unique_ptr<T>(new T(std::forward<Args>(args)...)); }
}
#endif

#define RE_UNUSED(x)                               (void)x
#define ENTRYPOINT_FUNCTION                        "entrypoint"
#define REGISTER_INVALID                           static_cast<s64>(-1)
#define BRANCH_DIRECTION(instruction, destination) (static_cast<s64>(destination) - static_cast<s64>(instruction->address))

namespace REDasm {

inline const std::string& searchPath() {  return Runtime::rntSearchPath; }
inline void log(const std::string& s) { Runtime::rntLogCallback(s); }
inline void status(const std::string& s) { Runtime::rntStatusCallback(s); }

template<typename... T> std::string makePath(const std::string& p1, const std::string& p2, T... args) {
    std::string path = p1 + Runtime::rntDirSeparator + p2;
    std::vector<std::string> v = { args... };

    for(size_t i = 0; i < v.size(); i++)
        path += Runtime::rntDirSeparator + v[i];

    return path;
}

template<typename...T> std::string makeRntPath(const std::string& p, T... args) { return REDasm::makePath(Runtime::rntSearchPath, p, args...); }
template<typename...T> std::string makeDbPath(const std::string& p, T... args) { return REDasm::makeRntPath("database", p, args...); }
template<typename...T> std::string makeFormatPath(const std::string& p, T... args) { return REDasm::makeDbPath("formats", p, args...); }

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
        None            = 0x00000000, Stop = 0x00000001, Nop = 0x00000002,
        Jump            = 0x00000004, Call = 0x00000008,
        Add             = 0x00000010, Sub  = 0x00000020, Mul = 0x00000040, Div = 0x0000080, Mod = 0x00000100, Lsh = 0x00000200, Rsh = 0x00000400,
        And             = 0x00000800, Or   = 0x00001000, Xor = 0x00002000, Not = 0x0004000,
        Push            = 0x00008000, Pop  = 0x00010000,
        Compare         = 0x00020000, Load = 0x00040000, Store = 0x00080000,

        Conditional     = 0x01000000, Privileged = 0x02000000,
        Invalid         = 0x10000000,
        Branch          = Jump | Call,
        ConditionalJump = Conditional | Jump,
        ConditionalCall = Conditional | Call,
    };
}

namespace OperandTypes {
    enum: u32 {
        None          = 0x00000000,
        Register      = 0x00000001,  // Register
        Immediate     = 0x00000002,  // Immediate Value
        Memory        = 0x00000004,  // Direct Memory Pointer
        Displacement  = 0x00000008,  // Indirect Memory Pointer

        Local         = 0x00010000,  // Local Variable
        Argument      = 0x00020000,  // Function Argument
    };
}

namespace OperandSizes {
    enum: u32 {
        Undefined  = 0,
        Byte       = 1,
        Word       = 2,
        Dword      = 4,
        Qword      = 8,
    };

    std::string size(u32 opsize);
}

/*
struct Buffer
{
    Buffer(): data(NULL), length(0) { }
    Buffer(u8* data, s64 length): data(data), length(length) { }
    Buffer(char* data, s64 length): data(reinterpret_cast<u8*>(data)), length(length) { }
    Buffer operator +(u64 v) const { Buffer b(data, length); b.data += v; b.length -= v; return b; }
    Buffer operator -(u64 v) const { Buffer b(data, length); b.data -= v; b.length += v; return b; }
    Buffer& operator +=(u64 v) { data += v; length -= v; return *this; }
    Buffer& operator -=(u64 v) { data += v; length += v; return *this; }
    Buffer operator++(int) { Buffer copy = *this; *this += 1; return copy; }
    Buffer& operator++() { *this += 1; return *this; }
    Buffer operator--(int) { Buffer copy = *this; *this -= 1; return copy; }
    Buffer& operator--() { *this -= 1; return *this; }
    u8 operator[](int index) const { return data[index]; }
    u8 operator*() const { return *data; }
    bool eob() const { return length <= 0; }
    template<typename T> operator T() const { return *reinterpret_cast<T*>(data); }

    u8* data;
    s64 length;
};
*/

struct Signature
{
    std::string name, pattern;
    u8 alen;
    u16 asum;

    Signature(): alen(0), asum(0) { }
    size_t length() const { return pattern.size(); }
};

struct Segment
{
    Segment(): offset(0), address(0), endaddress(0), type(0) { }
    Segment(const std::string& name, offset_t offset, address_t address, u64 size, u32 type): name(name), offset(offset), address(address), endaddress(address + size), type(type) { }
    s64 size() const { return static_cast<s64>(endaddress - address); }
    bool contains(address_t address) const { return (address >= this->address) && (address < endaddress); }
    bool is(u32 t) const { return type & t; }

    std::string name;
    offset_t offset;
    address_t address, endaddress;
    u32 type;
};

struct RegisterOperand
{
    RegisterOperand(): extra_type(0), r(REGISTER_INVALID) { }
    RegisterOperand(u64 type, register_t r): extra_type(type), r(r) { }
    RegisterOperand(register_t r): extra_type(0), r(r) { }

    u64 extra_type;
    register_t r;

    bool isValid() const { return r != REGISTER_INVALID; }
};

struct DisplacementOperand
{
    DisplacementOperand(): scale(1), displacement(0) { }
    DisplacementOperand(const RegisterOperand& base, const RegisterOperand& index, s32 scale, s64 displacement): base(base), index(index), scale(scale), displacement(displacement) { }

    RegisterOperand base, index;
    s32 scale;
    s64 displacement;
};

struct Operand
{
    Operand(): loc_index(-1), type(OperandTypes::None), extra_type(0), size(OperandSizes::Undefined), index(-1), u_value(0) { }
    Operand(u32 type, u32 extratype, s32 value, s64 idx): loc_index(-1), type(type), extra_type(extratype), size(OperandSizes::Undefined), index(idx), s_value(value) { }
    Operand(u32 type, u32 extratype, u32 value, s64 idx): loc_index(-1), type(type), extra_type(extratype), size(OperandSizes::Undefined), index(idx), u_value(value) { }
    Operand(u32 type, u32 extratype, s64 value, s64 idx): loc_index(-1), type(type), extra_type(extratype), size(OperandSizes::Undefined), index(idx), s_value(value) { }
    Operand(u32 type, u32 extratype, u64 value, s64 idx): loc_index(-1), type(type), extra_type(extratype), size(OperandSizes::Undefined), index(idx), u_value(value) { }

    s64 loc_index;
    u32 type, extra_type, size;
    s64 index;
    RegisterOperand reg;
    DisplacementOperand disp;

    union { s64 s_value; u64 u_value; };

    bool displacementIsDynamic() const { return is(OperandTypes::Displacement) && (disp.base.isValid() || disp.index.isValid()); }
    bool displacementCanBeAddress() const { return is(OperandTypes::Displacement) && (disp.displacement > 0); }
    bool isNumeric() const { return is(OperandTypes::Immediate) || is(OperandTypes::Memory); }
    bool is(u32 t) const { return type & t; }
};

struct Instruction
{
    Instruction(): address(0), target_idx(-1), type(0), size(0), id(0), userdata(NULL) { }
    ~Instruction() { reset(); }

    std::function<void(void*)> free;

    std::string mnemonic;
    std::set<address_t> targets;    // Jump/JumpTable/Call destination(s)
    std::vector<Operand> operands;
    address_t address;
    s32 target_idx;                 // Target's operand index
    u32 type, size;
    instruction_id_t id;            // Backend Specific
    void* userdata;                 // It doesn't survive after AssemblerPlugin::decode() by design

    bool is(u32 t) const { return type & t; }
    bool isTargetOperand(const Operand& op) const { return (target_idx == -1) ? false : (target_idx == op.index); }
    bool isInvalid() const { return type == InstructionTypes::Invalid; }
    bool hasTargets() const { return !targets.empty(); }
    void reset() { target_idx = -1, type = 0; targets.clear(); operands.clear(); if(free && userdata) { free(userdata); userdata = NULL; } }
    void targetOp(s32 index) { target_idx = index; targets.insert(operands[index].u_value); }
    void target(address_t target) { targets.insert(target); }
    void op_size(s32 index, u32 size) { operands[index].size = size; }
    u32 op_size(s32 index) const { return operands[index].size; }
    address_t target() const { return *targets.begin(); }
    address_t endAddress() const { return address + size; }

    Operand& targetOperand() { return operands[target_idx]; }
    Operand& op(size_t idx) { return operands[idx]; }
    Instruction& op(Operand op) { op.index = operands.size(); operands.push_back(op); return *this; }
    Instruction& mem(address_t v, u32 extratype = 0) { operands.push_back(Operand(OperandTypes::Memory, extratype, v, operands.size())); return *this; }
    template<typename T> Instruction& imm(T v, u32 extratype = 0) { operands.push_back(Operand(OperandTypes::Immediate, extratype, v, operands.size())); return *this; }
    template<typename T> Instruction& disp(register_t base, T displacement = 0) { return disp(base, REGISTER_INVALID, displacement); }
    template<typename T> Instruction& disp(register_t base, register_t index, T displacement) { return disp(base, index, 1, displacement); }
    template<typename T> Instruction& disp(register_t base, register_t index, s32 scale, T displacement);
    template<typename T> Instruction& arg(s64 index, register_t base, T displacement) { return local(index, base, displacement, OperandTypes::Argument); }
    template<typename T> Instruction& local(s64 index, register_t base, T displacement, u32 type = OperandTypes::Local);

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

    if((base == REGISTER_INVALID) && (index == REGISTER_INVALID))
    {
        op.type = OperandTypes::Memory;
        op.u_value = scale * displacement;
    }
    else
    {
        op.type = OperandTypes::Displacement;
        op.disp = DisplacementOperand(RegisterOperand(base), RegisterOperand(index), scale, displacement);
    }

    operands.push_back(op);
    return *this;
}

template<typename T> Instruction& Instruction::local(s64 index, register_t base, T displacement, u32 type)
{
    Operand op;
    op.index = operands.size();
    op.loc_index = index;
    op.type = OperandTypes::Displacement | type;
    op.disp = DisplacementOperand(RegisterOperand(base), RegisterOperand(index), 1, displacement);

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

#endif // REDASM_API_H
