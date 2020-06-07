#pragma once

#include <rdapi/rdapi.h>

class QtUI
{
    public:
        QtUI() = delete;
        static void initialize();

    public:
        static void message(const char* title, const char* text);
        static bool confirm(const char* title, const char* text);
        static int getItem(const char* title, const char* text, const RDUIOptions* options, size_t c);
        static bool getChecked(const char* title, const char* text, RDUIOptions* options, size_t c);
        static bool getText(const char* title, const char* text, char* outchar, size_t* size);
        static bool getDouble(const char* title, const char* text, double* outval);
        static bool getSigned(const char* title, const char* text, intptr_t* outval);
        static bool getUnsigned(const char* title, const char* text, intptr_t* outval);

    private:
        static RDUI m_rdui;
};
