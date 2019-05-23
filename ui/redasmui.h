#ifndef REDASMUI_H
#define REDASMUI_H

#include <QMainWindow>
#include <core/redasm.h>

class REDasmUI: public REDasm::AbstractUI
{
    public:
        REDasmUI(QMainWindow* mainwindow);
        virtual ~REDasmUI() = default;
        void checkList(const std::string& title, const std::string& text, std::deque<REDasm::UI::CheckListItem>& items) override;
        bool askYN(const std::string& title, const std::string& text) override;

    private:
        QMainWindow* m_mainwindow;
};

#endif // REDASMUI_H
