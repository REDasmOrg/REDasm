#include "redasmui.h"
#include "dialogui.h"
#include <QMessageBox>

REDasmUI::REDasmUI(QMainWindow *mainwindow): m_mainwindow(mainwindow) { }

void REDasmUI::checkList(const std::string &title, const std::string &text, std::deque<REDasm::UI::CheckListItem> &items)
{
    DialogUI dlgui(m_mainwindow);
    dlgui.setWindowTitle(QString::fromStdString(title));
    dlgui.setText(QString::fromStdString(text));
    dlgui.setItems(items);
    dlgui.exec();
}

bool REDasmUI::askYN(const std::string &title, const std::string &text)
{
    int res = QMessageBox::question(m_mainwindow,
                                    QString::fromStdString(title),
                                    QString::fromStdString(text),
                                    QMessageBox::Yes | QMessageBox::No);

    return res == QMessageBox::Yes;
}
