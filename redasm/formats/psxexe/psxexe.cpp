#include "psxexe.h"
#include "psxexe_analyzer.h"
#include <cstring>

#define PSXEXE_SIGNATURE      "PS-X EXE"
#define PSXEXE_TEXT_OFFSET    0x00000800

namespace REDasm {

PsxExeFormat::PsxExeFormat()
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

const char *PsxExeFormat::processor() const
{
    return "mips32";
}

Analyzer *PsxExeFormat::createAnalyzer() const
{
    return new PsxExeAnalyzer();
}

bool PsxExeFormat::load(u8* rawformat)
{
    PsxExeHeader* format = convert(rawformat);

    if(strncmp(format->id, PSXEXE_SIGNATURE, PSXEXE_SIGNATURE_SIZE))
        return false;

    this->defineSegment("TEXT", PSXEXE_TEXT_OFFSET, format->t_addr, format->t_size, SegmentTypes::Code | SegmentTypes::Data);
    this->defineEntryPoint(format->pc0);

    FormatPluginT<PsxExeHeader>::load(rawformat);
    return true;
}

}
