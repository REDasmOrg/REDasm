#include "mainwindow.h"
#include "themeprovider.h"
#include <QApplication>
#include <QtWebEngine>

#ifdef QT_DEBUG
#include "unittest/unittest.h"
#endif // QT_DEBUG

int main(int argc, char *argv[])
{
#ifdef QT_DEBUG
    if((argc == 2) && !std::strcmp(argv[1], "--testmode"))
        return UnitTest::run();
#endif // QT_DEBUG

    qRegisterMetaType<address_t>("address_t");

    QApplication a(argc, argv);
    a.setApplicationDisplayName("REDasm 2.0-" + QString::fromUtf8(GIT_VERSION) + " RC1");

    QtWebEngine::initialize();
    MainWindow w;

    w.show();
    return a.exec();
}
