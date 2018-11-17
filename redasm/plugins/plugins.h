#ifndef PLUGINS_H
#define PLUGINS_H

#include <unordered_map>
#include <string>
#include <list>
#include "format.h"
#include "assembler/assembler.h"

namespace REDasm {

extern std::list<FormatPlugin_Entry> formats;
extern std::unordered_map<std::string, AssemblerPlugin_Entry> assemblers;

FormatPlugin* getFormat(Buffer &buffer);
AssemblerPlugin* getAssembler(const char *id);
void setLoggerCallback(Runtime::LogCallback logcb);
void setStatusCallback(Runtime::LogCallback logcb);
void init(const std::string &searchpath);

}

#endif // PLUGINS_H
