#include "mainwindow.h"
#include "themeprovider.h"
#include <QApplication>
#include <QtWebEngine>
#include <QStyleFactory>
#include "redasmsettings.h"

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
    QApplication::setStyle(QStyleFactory::create("Fusion"));

    QApplication a(argc, argv);
    a.setOrganizationName("redasmorg");
    a.setApplicationName("redasm");
    a.setApplicationDisplayName("REDasm 2.0-" + QString::fromUtf8(REDASM_VERSION) + " RC3");

    QtWebEngine::initialize();

    REDasmSettings::setDefaultFormat(REDasmSettings::IniFormat);
    REDasmSettings settings;

    if(settings.isDarkTheme())
        ThemeProvider::selectDarkTheme();

    MainWindow w;

    w.show();
    return a.exec();
}
