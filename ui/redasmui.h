#ifndef REDASMUI_H
#define REDASMUI_H

#include <QMainWindow>
#include <redasm/redasm.h>

class REDasmUI: public REDasm::AbstractUI
{
    public:
        REDasmUI(QMainWindow* mainwindow);
        virtual ~REDasmUI() = default;
        int select(const REDasm::String& title, const REDasm::String &text, const REDasm::List& items) override;
        void checkList(const REDasm::String& title, const REDasm::String& text, std::deque<REDasm::UI::CheckListItem>& items) override;
        bool askYN(const REDasm::String& title, const REDasm::String& text) override;

    private:
        QMainWindow* m_mainwindow;
};

#endif // REDASMUI_H
