#define WRAP_TO_STRING(...)         #__VA_ARGS__
#define FORMAT_PLUGIN(format)       WRAP_TO_STRING(../formats/format/format.h)
#define ASSEMBLER_PLUGIN(assembler) WRAP_TO_STRING(../assemblers/assembler/assembler.h)

#include "plugins.h"

/* *** Formats *** */
#include FORMAT_PLUGIN(binary)
#include FORMAT_PLUGIN(pe)
#include FORMAT_PLUGIN(elf)
#include FORMAT_PLUGIN(psxexe)
#include FORMAT_PLUGIN(dex)
#include FORMAT_PLUGIN(xbe)
#include FORMAT_PLUGIN(gba)

/* *** Assemblers *** */
#include ASSEMBLER_PLUGIN(x86)
#include ASSEMBLER_PLUGIN(mips)
#include ASSEMBLER_PLUGIN(dalvik)
#include ASSEMBLER_PLUGIN(cil)
#include ASSEMBLER_PLUGIN(metaarm)
//#include ASSEMBLER_PLUGIN(arm64)
#include ASSEMBLER_PLUGIN(chip8)

#define REGISTER_FORMAT_PLUGIN(id)    REDasm::formats.push_back(&id##_formatPlugin)
#define REGISTER_ASSEMBLER_PLUGIN(id) REDasm::assemblers[#id] = &id##_assemblerPlugin

namespace REDasm {

EntryListT<FormatPlugin_Entry>::Type formats;
EntryMapT<AssemblerPlugin_Entry>::Type assemblers;

void init(const std::string& searchpath)
{
    Runtime::rntSearchPath = searchpath;

    REGISTER_FORMAT_PLUGIN(pe);
    REGISTER_FORMAT_PLUGIN(elf32);
    REGISTER_FORMAT_PLUGIN(elf64);
    REGISTER_FORMAT_PLUGIN(psxexe);
    REGISTER_FORMAT_PLUGIN(dex);
    REGISTER_FORMAT_PLUGIN(xbe);
    REGISTER_FORMAT_PLUGIN(gbarom);
    REGISTER_FORMAT_PLUGIN(binary); // Always last choice

    REGISTER_ASSEMBLER_PLUGIN(x86_16);
    REGISTER_ASSEMBLER_PLUGIN(x86_32);
    REGISTER_ASSEMBLER_PLUGIN(x86_64);
    REGISTER_ASSEMBLER_PLUGIN(mips32);
    REGISTER_ASSEMBLER_PLUGIN(mips64);
    REGISTER_ASSEMBLER_PLUGIN(arm);
    REGISTER_ASSEMBLER_PLUGIN(armthumb);
    REGISTER_ASSEMBLER_PLUGIN(metaarm);
    //REGISTER_ASSEMBLER_PLUGIN(arm64);
    REGISTER_ASSEMBLER_PLUGIN(dalvik);
    REGISTER_ASSEMBLER_PLUGIN(cil);
    REGISTER_ASSEMBLER_PLUGIN(chip8);
}

FormatPlugin *getFormat(Buffer& buffer)
{
    for(FormatPlugin_Entry formatentry : formats)
    {
        FormatPlugin* fp = formatentry(buffer);

        if(fp)
            return fp;
    }

    return NULL;
}

AssemblerPlugin *getAssembler(const char* id)
{
    auto it = REDasm::findPluginEntry<AssemblerPlugin_Entry>(id, assemblers);

    if(it != assemblers.end())
        return it->second();

    return NULL;
}

void setLoggerCallback(Runtime::LogCallback logcb) { Runtime::rntLogCallback = logcb; }
void setStatusCallback(Runtime::LogCallback logcb) { Runtime::rntStatusCallback = logcb; }

}
