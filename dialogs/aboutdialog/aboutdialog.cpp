#include "aboutdialog.h"
#include "ui_aboutdialog.h"
#include "../../themeprovider.h"
#include <QPushButton>
#include <QPainter>
#include <vector>

AboutDialog::AboutDialog(QWidget *parent) : QDialog(parent), ui(new Ui::AboutDialog)
{
    ui->setupUi(this);
    ui->lblHeader->setText(QString(ui->lblHeader->text()).arg(REDASM_VERSION, QT_VERSION_STR));

    this->setStyleSheet("QTextEdit {"
                            "background: transparent;"
                            "border: 0;"
                        "}");

    this->initDependencies();

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
    cursor.insertHtml("<b>Thanks to:</b><br>");

    for(const auto& [name, url] : DEPENDENCIES)
    {
        cursor.insertHtml(QString("- <a href='%1'>%2</a>").arg(url, name));
        if(name != DEPENDENCIES.back().first) cursor.insertText("\n");
    }
}
