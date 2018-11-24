#ifndef PLUGINS_H
#define PLUGINS_H

#include <unordered_map>
#include <string>
#include <list>
#include "format.h"
#include "assembler/assembler.h"

namespace REDasm {

template<typename T> struct PluginMapT { typedef std::unordered_map<std::string, T> Type; };

template<typename T> typename PluginMapT<T>::Type::const_iterator findPluginEntry(const char* id, const typename PluginMapT<T>::Type& pm)
{
    if(!id)
        return pm.end();

    return pm.find(id);
}

extern PluginMapT<FormatPlugin_Entry>::Type formats;
extern PluginMapT<AssemblerPlugin_Entry>::Type assemblers;

FormatPlugin* getFormat(Buffer &buffer);
FormatPlugin_Entry getFormat(const char* id);
AssemblerPlugin* getAssembler(const char* id);
void setLoggerCallback(Runtime::LogCallback logcb);
void setStatusCallback(Runtime::LogCallback logcb);
void init(const std::string &searchpath);

}

#endif // PLUGINS_H
