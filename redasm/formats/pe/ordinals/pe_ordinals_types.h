#ifndef PE_ORDINALS_TYPES_H
#define PE_ORDINALS_TYPES_H

#include "../../../redasm.h"

#define COMPILE_MAP(dll, classid) _libraries[dll] = OrdinalMap(); \
                                  classid::compile(_libraries[dll]);

#define ORDINAL_NAME(ord, name) m[ord] = name;

typedef std::map<u16, std::string> OrdinalMap;
typedef std::map<std::string, OrdinalMap> ResolveMap;

#endif // PE_ORDINALS_TYPES_H
