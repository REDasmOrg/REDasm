#include "mainwindow.h"
#include <QApplication>
#include <QtWebEngine>

#ifdef QT_DEBUG
#include "unittest/unittest.h"
#endif // QT_DEBUG

int main(int argc, char *argv[])
{
    qRegisterMetaType<address_t>("address_t");

    QApplication a(argc, argv);
    a.setApplicationDisplayName("REDasm 2.0-" + QString::fromUtf8(GIT_VERSION));

    QtWebEngine::initialize();
    MainWindow w;

#ifdef QT_DEBUG
    if(a.arguments().contains("--testmode", Qt::CaseInsensitive))
        return UnitTest::run();
#endif // QT_DEBUG

    w.show();
    return a.exec();
}
