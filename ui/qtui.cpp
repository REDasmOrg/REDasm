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

    RD_SetUI(&m_rdui);
}

void QtUI::message(const char* title, const char* text)
{
    QMetaObject::invokeMethod(QtUI::instance(), "messageImpl", Qt::BlockingQueuedConnection,
                              Q_ARG(const char*, title), Q_ARG(const char*, text));
}

bool QtUI::confirm(const char* title, const char* text)
{
    bool res = false;

    QMetaObject::invokeMethod(QtUI::instance(), "confirmImpl", Qt::BlockingQueuedConnection,
                              Q_RETURN_ARG(bool, res),
                              Q_ARG(const char*, title), Q_ARG(const char*, text));

    return res;
}

int QtUI::getItem(const char* title, const char* text, const RDUIOptions* options, size_t c)
{
    int res = -1;

    QMetaObject::invokeMethod(QtUI::instance(), "getItemImpl", Qt::BlockingQueuedConnection,
                              Q_RETURN_ARG(int, res),
                              Q_ARG(const char*, title), Q_ARG(const char*, text),
                              Q_ARG(const RDUIOptions*, options), Q_ARG(size_t, c));

    return res;
}

bool QtUI::getChecked(const char* title, const char* text, RDUIOptions* options, size_t c)
{
    int res = false;

    QMetaObject::invokeMethod(QtUI::instance(), "getCheckedImpl", Qt::BlockingQueuedConnection,
                              Q_RETURN_ARG(int, res),
                              Q_ARG(const char*, title), Q_ARG(const char*, text),
                              Q_ARG(RDUIOptions*, options), Q_ARG(size_t, c));

    return res;
}

bool QtUI::getText(const char* title, const char* text, char* outchar, size_t* size)
{
    bool res = false;

    QMetaObject::invokeMethod(QtUI::instance(), "getTextImpl", Qt::BlockingQueuedConnection,
                              Q_RETURN_ARG(bool, res),
                              Q_ARG(const char*, title), Q_ARG(const char*, text),
                              Q_ARG(char*, outchar), Q_ARG(size_t*, size));

    return res;
}

bool QtUI::getDouble(const char* title, const char* text, double* outval)
{
    bool res = false;

    QMetaObject::invokeMethod(QtUI::instance(), "getDoubleImpl", Qt::BlockingQueuedConnection,
                              Q_RETURN_ARG(bool, res),
                              Q_ARG(const char*, title), Q_ARG(const char*, text),
                              Q_ARG(double*, outval));

    return res;
}

bool QtUI::getSigned(const char* title, const char* text, intptr_t* outval)
{
    bool res = false;

    QMetaObject::invokeMethod(QtUI::instance(), "getSignedImpl", Qt::BlockingQueuedConnection,
                              Q_RETURN_ARG(bool, res),
                              Q_ARG(const char*, title), Q_ARG(const char*, text),
                              Q_ARG(intptr_t*, outval));

    return res;
}

bool QtUI::getUnsigned(const char* title, const char* text, uintptr_t* outval)
{
    bool res = false;

    QMetaObject::invokeMethod(QtUI::instance(), "getUnsignedImpl", Qt::BlockingQueuedConnection,
                              Q_RETURN_ARG(bool, res),
                              Q_ARG(const char*, title), Q_ARG(const char*, text),
                              Q_ARG(uintptr_t*, outval));

    return res;
}

QtUI::QtUI(QObject* parent): QObject(parent) { }

QtUI* QtUI::instance()
{
    static QtUI m_qtui;
    return &m_qtui;
}

void QtUI::messageImpl(const char* title, const char* text)
{
    QMessageBox msgbox;
    msgbox.setWindowTitle(title);
    msgbox.setText(text);
    msgbox.exec();
}

bool QtUI::confirmImpl(const char* title, const char* text)
{
     int res = QMessageBox::question(nullptr, title, text,
                                     QMessageBox::Yes | QMessageBox::No);

     return res == QMessageBox::Yes;
}

int QtUI::getItemImpl(const char* title, const char* text, const RDUIOptions* options, size_t c)
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

bool QtUI::getCheckedImpl(const char* title, const char* text, RDUIOptions* options, size_t c)
{
    QtDialogUI dlgui;
    dlgui.setWindowTitle(title);
    dlgui.setText(text);
    dlgui.setCheckedOptions(options, c);
    return dlgui.exec() == QtDialogUI::Accepted;
}

bool QtUI::getTextImpl(const char* title, const char* text, char* outchar, size_t* size)
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

bool QtUI::getDoubleImpl(const char* title, const char* text, double* outval)
{
    bool ok = false;

    double val = QInputDialog::getDouble(nullptr, title, text, 0,
                                         std::numeric_limits<double>::min(),
                                         std::numeric_limits<double>::max(),
                                         1, &ok);

    if(ok && outval) *outval = val;
    return ok;
}

bool QtUI::getSignedImpl(const char* title, const char* text, intptr_t* outval)
{

    bool ok = false;

    intptr_t val = QInputDialog::getInt(nullptr, title, text, 0,
                                        std::numeric_limits<int>::min(),
                                        std::numeric_limits<int>::max(),
                                        1, &ok);

    if(ok && outval) *outval = val;
    return ok;
}

bool QtUI::getUnsignedImpl(const char* title, const char* text, uintptr_t* outval)
{
    bool ok = false;

    intptr_t val = QInputDialog::getInt(nullptr, title, text, 0,
                                        std::numeric_limits<unsigned int>::min(),
                                        std::numeric_limits<unsigned int>::max(),
                                        1, &ok);

    if(ok && outval) *outval = val;
    return ok;
}
