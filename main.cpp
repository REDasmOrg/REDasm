#include "mainwindow.h"
#include "themeprovider.h"
#include "redasmsettings.h"
#include <cstring>
#include <rdapi/rdapi.h>
#include <QApplication>
#include <QStyleFactory>

#ifdef QT_DEBUG
    #include "unittest/unittest.h"
#endif // QT_DEBUG

int main(int argc, char *argv[])
{
#ifdef QT_DEBUG
    if((argc == 2) && !std::strcmp(argv[1], "--testmode"))
        return UnitTest::run();
#endif // QT_DEBUG

    qRegisterMetaType<size_t>("size_t");
    qRegisterMetaType<rd_address>("address_t");
    QApplication::setStyle(QStyleFactory::create("Fusion"));

    QApplication a(argc, argv);
    a.setOrganizationName("redasm.io");
    a.setApplicationName("redasm");
    a.setApplicationDisplayName("REDasm 3.0-" + QString::fromUtf8(REDASM_VERSION));

    REDasmSettings::setDefaultFormat(REDasmSettings::IniFormat);
    ThemeProvider::applyTheme();
    MainWindow w;
    w.show();
    return a.exec();
}
