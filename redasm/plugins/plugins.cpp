#include "plugins.h"
#include "../formats/binary/binary.h"
#include "../formats/pe/pe.h"
#include "../formats/elf/elf.h"
#include "../formats/psxexe/psxexe.h"
#include "../formats/dex/dex.h"
#include "../processors/x86/x86.h"
#include "../processors/mips/mips.h"
#include "../processors/arm/arm.h"
//#include "../processors/arm/arm64.h"
#include "../processors/chip8/chip8.h"

#define REGISTER_FORMAT_PLUGIN(id)    REDasm::formats.push_back(&id##_formatPlugin)
#define REGISTER_PROCESSOR_PLUGIN(id) REDasm::processors[#id] = &id##_processorPlugin

namespace REDasm {

std::list<FormatPlugin_Entry> formats;
std::unordered_map<std::string, ProcessorPlugin_Entry> processors;

void init(const std::string& searchpath)
{
    Runtime::rntSearchPath = searchpath;

    REGISTER_FORMAT_PLUGIN(pe);
    REGISTER_FORMAT_PLUGIN(elf32);
    REGISTER_FORMAT_PLUGIN(elf64);
    REGISTER_FORMAT_PLUGIN(psxexe);
    REGISTER_FORMAT_PLUGIN(dex);
    REGISTER_FORMAT_PLUGIN(binary); // Always last choice

    REGISTER_PROCESSOR_PLUGIN(x86_16);
    REGISTER_PROCESSOR_PLUGIN(x86_32);
    REGISTER_PROCESSOR_PLUGIN(x86_64);
    REGISTER_PROCESSOR_PLUGIN(mips32);
    REGISTER_PROCESSOR_PLUGIN(mips64);
    REGISTER_PROCESSOR_PLUGIN(arm);
    //REGISTER_PROCESSOR_PLUGIN(arm64);
    REGISTER_PROCESSOR_PLUGIN(chip8);
}

FormatPlugin *getFormat(u8 *data)
{
    if(!data)
        return NULL;

    for(auto it = formats.begin(); it != formats.end(); it++)
    {
        FormatPlugin* fp = (*it)(data);

        if(fp)
            return fp;
    }

    return NULL;
}

ProcessorPlugin *getProcessor(const char* id)
{
    if(!id)
        return NULL;

    auto it = processors.find(id);

    if(it == processors.end())
        return NULL;

    return (it->second)();
}

void setLoggerCallback(Runtime::LogCallback logcb) { Runtime::rntLogCallback = logcb; }
void setStatusCallback(Runtime::LogCallback logcb) { Runtime::rntStatusCallback = logcb; }

}
