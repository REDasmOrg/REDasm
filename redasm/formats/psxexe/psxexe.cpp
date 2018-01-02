#include "psxexe.h"
#include "psxexe_analyzer.h"
#include <cstring>

#define PSXEXE_SIGNATURE   "PS-X EXE"
#define PSXEXE_TEXT_OFFSET 0x00000800
#define PSX_USER_RAM_START 0x80000000
#define PSX_USER_RAM_END   0x80200000

namespace REDasm {

PsxExeFormat::PsxExeFormat(): FormatPluginT<PsxExeHeader>()
{

}

const char *PsxExeFormat::name() const
{
    return "PS-X Executable";
}

u32 PsxExeFormat::bits() const
{
    return 32;
}

const char *PsxExeFormat::assembler() const
{
    return "mips32";
}

Analyzer *PsxExeFormat::createAnalyzer(DisassemblerFunctions *dfunctions, const SignatureFiles &signatures) const
{
    return new PsxExeAnalyzer(dfunctions, signatures);
}

bool PsxExeFormat::load(u8* rawformat)
{
    PsxExeHeader* format = convert(rawformat);

    if(strncmp(format->id, PSXEXE_SIGNATURE, PSXEXE_SIGNATURE_SIZE))
        return false;

    if(format->t_addr > PSX_USER_RAM_START)
        this->defineSegment("RAM0", 0, PSX_USER_RAM_START, (format->t_addr - PSX_USER_RAM_START), SegmentTypes::Data | SegmentTypes::Bss);

    this->addSignature("psyq47");
    this->defineSegment("TEXT", PSXEXE_TEXT_OFFSET, format->t_addr, format->t_size, SegmentTypes::Code | SegmentTypes::Data);

    if((format->t_addr + format->t_size) < PSX_USER_RAM_END)
        this->defineSegment("RAM1", 0, format->t_addr + format->t_size, PSX_USER_RAM_END - (format->t_addr + format->t_size), SegmentTypes::Data | SegmentTypes::Bss);

    this->defineEntryPoint(format->pc0);

    FormatPluginT<PsxExeHeader>::load(rawformat);
    return true;
}

}
