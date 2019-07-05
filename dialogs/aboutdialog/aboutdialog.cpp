#include "aboutdialog.h"
#include "ui_aboutdialog.h"
#include "../../themeprovider.h"
#include "../../convert.h"
#include <redasm/context.h>

AboutDialog::AboutDialog(QWidget *parent) : QDialog(parent), ui(new Ui::AboutDialog)
{
    ui->setupUi(this);
    ui->twDepends->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    ui->twDepends->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    ui->twDepends->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);

    this->initItems();
    this->initDepends();

    if(ThemeProvider::isDarkTheme())
        ui->lblLogo->setPixmap(QPixmap(QString::fromUtf8(":/res/logo_big_dark.png")));
    else
        ui->lblLogo->setPixmap(QPixmap(QString::fromUtf8(":/res/logo_big.png")));

    connect(ui->buttonBox, &QDialogButtonBox::accepted, this, &AboutDialog::accept);
}

AboutDialog::~AboutDialog() { delete ui; }

void AboutDialog::initItems()
{
    QString csversion = Convert::to_qstring(r_ctx->capstoneVersion());

    m_depends.push_back({ "Qt",           QT_VERSION_STR, "https://www.qt.io" });
    m_depends.push_back({ "Capstone",     csversion,      "https://www.capstone-engine.org" });
    m_depends.push_back({ "JSON",         "---",          "https://github.com/nlohmann/json" });
    m_depends.push_back({ "UndName",      "---",          "https://github.com/wine-mirror/wine/blob/master/dlls/msvcrt/undname.c" });
    m_depends.push_back({ "Libiberty",    "---",          "https://github.com/bminor/binutils-gdb/tree/master/libiberty" });
    m_depends.push_back({ "Visit-Struct", "---",          "https://github.com/cbeck88/visit_struct" });
}

void AboutDialog::initDepends()
{
    ui->twDepends->setRowCount(static_cast<int>(m_depends.size()));

    for(auto it = m_depends.begin(); it != m_depends.end(); it++)
    {
        int index = std::distance(m_depends.begin(), it);

        ui->twDepends->setItem(index, 0, new QTableWidgetItem(it->name));
        ui->twDepends->setItem(index, 1, new QTableWidgetItem(it->version));

        auto urlitem = new QTableWidgetItem(it->url);
        urlitem->setTextAlignment(Qt::AlignCenter);
        ui->twDepends->setItem(index, 2, urlitem);
    }
}
