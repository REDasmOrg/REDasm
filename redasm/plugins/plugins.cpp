#define WRAP_TO_STRING(...)         #__VA_ARGS__
#define FORMAT_PLUGIN(format)       WRAP_TO_STRING(../formats/format/format.h)
#define PROCESSOR_PLUGIN(processor) WRAP_TO_STRING(../processors/processor/processor.h)

#include "plugins.h"

/* *** Formats *** */
#include FORMAT_PLUGIN(binary)
#include FORMAT_PLUGIN(pe)
#include FORMAT_PLUGIN(elf)
#include FORMAT_PLUGIN(psxexe)
#include FORMAT_PLUGIN(dex)

/* *** Processors *** */
#include PROCESSOR_PLUGIN(x86)
#include PROCESSOR_PLUGIN(mips)
#include PROCESSOR_PLUGIN(arm)
#include PROCESSOR_PLUGIN(dalvik)
//#include PROCESSOR_PLUGIN(arm64)
#include PROCESSOR_PLUGIN(chip8)

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
    REGISTER_PROCESSOR_PLUGIN(dalvik);
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
