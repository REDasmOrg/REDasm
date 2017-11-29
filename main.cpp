#include "mainwindow.h"
#include <QApplication>

#ifdef QT_DEBUG
#include "unittest/unittest.h"
#endif // QT_DEBUG

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    a.setApplicationDisplayName("REDasm 1.0");

    MainWindow w;

#ifdef QT_DEBUG
    if(a.arguments().contains("--testmode", Qt::CaseInsensitive))
        return UnitTest::run();
#endif // QT_DEBUG

    w.show();
    return a.exec();
}
