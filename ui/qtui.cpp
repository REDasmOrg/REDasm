#include "qtui.h"
#include "qtdialogui.h"
#include <QInputDialog>
#include <QMessageBox>
#include <limits>

RDUI QtUI::m_rdui{ };

void QtUI::initialize()
{
    QtUI::instance(); // Initialize QtUI in UI thread

    m_rdui.message = &QtUI::message;
    m_rdui.confirm = &QtUI::confirm;
    m_rdui.getitem = &QtUI::getItem;
    m_rdui.getchecked = &QtUI::getChecked;
    m_rdui.gettext = &QtUI::getText;
    m_rdui.getdouble = &QtUI::getDouble;
    m_rdui.getsigned = &QtUI::getSigned;
    m_rdui.getunsigned = &QtUI::getUnsigned;

    RDConfig_SetUI(&m_rdui);
}

void QtUI::message(const char* title, const char* text)
{
    QMessageBox msgbox;
    msgbox.setWindowTitle(title);
    msgbox.setText(text);
    msgbox.exec();
}

bool QtUI::confirm(const char* title, const char* text)
{
    int res = QMessageBox::question(nullptr, title, text,
                                    QMessageBox::Yes | QMessageBox::No);

    return res == QMessageBox::Yes;
}

int QtUI::getItem(const char* title, const char* text, const RDUIOptions* options, size_t c)
{
    int selectedidx = 0;
    QStringList items;

    for(size_t i = 0; i < c; i++)
    {
        items.push_back(options[i].text);
        if(options[i].selected) selectedidx = i;
    }

    bool ok;
    QString item = QInputDialog::getItem(nullptr, title, text, items, selectedidx, false, &ok);
    if(!ok || item.isEmpty()) return -1;
    return items.indexOf(item);
}

bool QtUI::getChecked(const char* title, const char* text, RDUIOptions* options, size_t c)
{
    QtDialogUI dlgui;
    dlgui.setWindowTitle(title);
    dlgui.setText(text);
    dlgui.setCheckedOptions(options, c);
    return dlgui.exec() == QtDialogUI::Accepted;
}

bool QtUI::getText(const char* title, const char* text, char* outchar, size_t* size)
{
    bool ok = false;

    QString s = QInputDialog::getText(nullptr, title, text, QLineEdit::Normal, QString(), &ok);

    if(ok)
    {
        if(outchar) std::copy_n(s.toUtf8().constData(), std::min<size_t>(s.size(), *size), outchar);
        if(size) *size = s.size();
    }

    return ok;
}

bool QtUI::getDouble(const char* title, const char* text, double* outval)
{
    bool ok = false;

    double val = QInputDialog::getDouble(nullptr, title, text, 0,
                                         std::numeric_limits<double>::min(),
                                         std::numeric_limits<double>::max(),
                                         1, &ok);

    if(ok && outval) *outval = val;
    return ok;
}

bool QtUI::getSigned(const char* title, const char* text, intptr_t* outval)
{
    bool ok = false;

    intptr_t val = QInputDialog::getInt(nullptr, title, text, 0,
                                        std::numeric_limits<int>::min(),
                                        std::numeric_limits<int>::max(),
                                        1, &ok);

    if(ok && outval) *outval = val;
    return ok;
}

bool QtUI::getUnsigned(const char* title, const char* text, uintptr_t* outval)
{
    bool ok = false;

    intptr_t val = QInputDialog::getInt(nullptr, title, text, 0,
                                        std::numeric_limits<unsigned int>::min(),
                                        std::numeric_limits<unsigned int>::max(),
                                        1, &ok);

    if(ok && outval) *outval = val;
    return ok;
}

QtUI::QtUI(QObject* parent): QObject(parent) { }

QtUI* QtUI::instance()
{
    static QtUI m_qtui;
    return &m_qtui;
}
