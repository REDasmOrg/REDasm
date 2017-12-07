#ifndef PLUGINS_H
#define PLUGINS_H

#include <unordered_map>
#include <string>
#include <list>
#include "format.h"
#include "processor/processor.h"

namespace REDasm {

extern std::list<FormatPlugin_Entry> formats;
extern std::unordered_map<std::string, ProcessorPlugin_Entry> processors;

FormatPlugin* getFormat(u8* data);
ProcessorPlugin* getProcessor(const char *id);
void init(const std::string &searchpath);

}

#endif // PLUGINS_H
