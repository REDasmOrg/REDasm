#pragma once

#include <QString>
#include <redasm/types/string.h>

class Convert
{
    public:
        Convert() = delete;
        static inline QString to_qstring(const REDasm::String& s) { return QString::fromUtf8(s.c_str()); }
        static inline REDasm::String to_rstring(const QString& s) { return qUtf8Printable(s); }
};
