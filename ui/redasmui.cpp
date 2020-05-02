#include "redasmui.h"
#include <QMessageBox>

// REDasmUI::REDasmUI(QMainWindow *mainwindow): m_mainwindow(mainwindow) { }
//
// int REDasmUI::select(const REDasm::String &title, const REDasm::String& text, const REDasm::List &items)
// {
//     DialogUI dlgui(m_mainwindow);
//     //dlgui.setWindowTitle(Convert::to_qstring(title));
//     //dlgui.setText(Convert::to_qstring(text));
//     dlgui.selectableItems(items);
//     return (dlgui.exec() == DialogUI::Accepted) ? dlgui.selectedIndex() : -1;
// }
//
// void REDasmUI::checkList(const REDasm::String &title, const REDasm::String &text, std::deque<REDasm::UI::CheckListItem> &items)
// {
//     DialogUI dlgui(m_mainwindow);
//     //dlgui.setWindowTitle(Convert::to_qstring(title));
//     //dlgui.setText(Convert::to_qstring(text));
//     dlgui.setItems(items);
//     dlgui.exec();
// }
//
// bool REDasmUI::askYN(const REDasm::String &title, const REDasm::String &text)
// {
//     //int res = QMessageBox::question(m_mainwindow,
//                                     //Convert::to_qstring(title),
//                                     //Convert::to_qstring(text),
//                                     //QMessageBox::Yes | QMessageBox::No);
//
//     //return res == QMessageBox::Yes;
// }
//
