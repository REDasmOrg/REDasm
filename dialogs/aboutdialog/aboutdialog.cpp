#include "aboutdialog.h"
#include "ui_aboutdialog.h"
#include "../../redasmsettings.h"
#include "../../themeprovider.h"
#include <rdapi/rdapi.h>
#include <QPushButton>
#include <QPainter>
#include <vector>

AboutDialog::AboutDialog(QWidget *parent) : QDialog(parent), ui(new Ui::AboutDialog)
{
    ui->setupUi(this);
    ui->lblVersion->setText(REDASM_VERSION);
    ui->lblQtVersion->setText(QT_VERSION_STR);
    ui->lblLibREDasmVersion->setText(LIBREDASM_VERSION);
    ui->lblRDApiLevel->setText(QString::number(RDAPI_LEVEL));

    ui->tbDependencies->setStyleSheet("QTextEdit {"
                                        "background: transparent;"
                                        "border: 0;"
                                      "}");

    this->initDependencies();
    this->initSearchPaths();

    if(ThemeProvider::isDarkTheme()) ui->lblLogo->setPixmap(QPixmap(":/res/logo_dark.png"));
    else ui->lblLogo->setPixmap(QPixmap(":/res/logo.png"));

    connect(ui->buttonBox, &QDialogButtonBox::clicked, this, &AboutDialog::accept);
}

AboutDialog::~AboutDialog() { delete ui; }

void AboutDialog::initDependencies()
{
    static const std::vector<std::pair<QString, QString>> DEPENDENCIES = {
        {"TaoJSON", "https://github.com/taocpp/json" },
        {"UndName", "https://github.com/wine-mirror/wine/blob/master/dlls/msvcrt/undname.c"},
        {"Libiberty", "https://github.com/bminor/binutils-gdb/tree/master/libiberty"},
    };

    QTextCursor cursor(ui->tbDependencies->document());
    QTextListFormat lf;
    lf.setStyle(QTextListFormat::ListDisc);
    cursor.insertList(lf);

    for(const auto& [name, url] : DEPENDENCIES)
    {
        QTextCharFormat cf;
        cf.setAnchor(true);
        cf.setAnchorHref(url);
        cf.setForeground(qApp->palette().brush(QPalette::Highlight));
        cursor.insertText(" " + name, cf);
        if(name != DEPENDENCIES.back().first) cursor.insertText("\n");
    }
}

void AboutDialog::initSearchPaths()
{
    RDConfig_GetPluginPaths([](const char* path, void* userdata) {
        auto* thethis = reinterpret_cast<QListWidget*>(userdata);
        thethis->addItem(path);
    }, ui->lwPluginPaths);

    RDConfig_GetDatabasePaths([](const char* path, void* userdata) {
        auto* thethis = reinterpret_cast<QListWidget*>(userdata);
        thethis->addItem(path);
    }, ui->lwDatabasePaths);
}
