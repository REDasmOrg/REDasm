#include "mainwindow.h"
#include "themeprovider.h"
#include "redasmsettings.h"
#include <QApplication>
#include <QStyleFactory>

int main(int argc, char *argv[])
{
    qRegisterMetaType<size_t>("size_t");
    qRegisterMetaType<rd_address>("address_t");
    QApplication::setStyle(QStyleFactory::create("Fusion"));

    QApplication a(argc, argv);
    a.setApplicationName("redasm");
    a.setApplicationDisplayName("REDasm " + QString::fromUtf8(REDASM_VERSION));

    REDasmSettings::setDefaultFormat(REDasmSettings::IniFormat);
    ThemeProvider::applyTheme();
    MainWindow w;
    w.show();
    return a.exec();
}
