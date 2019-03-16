#ifndef REDASMUI_H
#define REDASMUI_H

#include <QMainWindow>
#include <redasm/redasm.h>

class REDasmUI: public REDasm::AbstractUI
{
    public:
        REDasmUI(QMainWindow* mainwindow);
        virtual ~REDasmUI() = default;
        virtual bool askYN(const std::string& title, const std::string& text);

    private:
        QMainWindow* m_mainwindow;
};

#endif // REDASMUI_H
