#include "redasmui.h"
#include <QMessageBox>

REDasmUI::REDasmUI(QMainWindow *mainwindow): m_mainwindow(mainwindow) { }

bool REDasmUI::askYN(const std::string &title, const std::string &text)
{
    int res = QMessageBox::question(m_mainwindow,
                                    QString::fromStdString(title),
                                    QString::fromStdString(text),
                                    QMessageBox::Yes | QMessageBox::No);

    return res == QMessageBox::Yes;
}
