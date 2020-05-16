#include "welcometab.h"
#include "ui_welcometab.h"
#include "../../../delegates/recentfilesdelegate.h"
#include "../../../models/recentfilesmodel.h"
#include "../../../hooks/disassemblerhooks.h"
#include "../../../redasmsettings.h"
#include "../../../redasmfonts.h"
#include <QDesktopServices>
#include <QFileInfo>
#include <QUrl>

WelcomeTab::WelcomeTab(QWidget *parent) : QWidget(parent), ui(new Ui::WelcomeTab)
{
    ui->setupUi(this);

    QString brandtext = QString("<p style='font-size: 60px; font-weight: bold;'>"
                                    "<span style='color:#a80a2b;'>RE</span>"
                                    "Dasm"
                                "</p>"
                                "<span>Version 3.0-%1</span>").arg(REDASM_VERSION);

    ui->lblBrand->setFont(qApp->font());
    ui->lblBrand->setText(brandtext);

    ui->lvRecentFiles->viewport()->setAttribute(Qt::WA_Hover);
    ui->lvRecentFiles->viewport()->setBackgroundRole(QPalette::Window);
    this->setAutoFillBackground(true);

    QString flatstylesheet = QString("QPushButton:hover {"
                                         "background-color: %1;"
                                     "}").arg(this->palette().color(QPalette::Window).darker(125).name());

    QString borderedstylesheet = QString("QPushButton {"
                                             "border-color: %1;"
                                             "border-style: solid;"
                                             "border-width: 1px;"
                                         "}"
                                         "%2").arg(this->palette().color(QPalette::Text).name(), flatstylesheet);

    QString socialstylesheet = QString("QPushButton {"
                                           "text-align: left;"
                                       "}");

    ui->pbOpen->setCursor(Qt::PointingHandCursor);
    ui->pbOpen->setStyleSheet(borderedstylesheet);
    ui->pbSettings->setCursor(Qt::PointingHandCursor);
    ui->pbSettings->setStyleSheet(borderedstylesheet);
    ui->pbAbout->setCursor(Qt::PointingHandCursor);
    ui->pbAbout->setStyleSheet(borderedstylesheet);

    this->styleSocialButton(ui->pbREDasmIO, FA_ICON(0xf015));
    this->styleSocialButton(ui->pbTelegram, FAB_ICON(0xf3fe));
    this->styleSocialButton(ui->pbReddit, FAB_ICON(0xf281));
    this->styleSocialButton(ui->pbGitHub, FAB_ICON(0xf113));

    RecentFilesModel* recentfilesmodel = new RecentFilesModel(ui->lvRecentFiles);
    recentfilesmodel->update();

    ui->lvRecentFiles->setItemDelegate(new RecentFilesDelegate(ui->lvRecentFiles));
    ui->lvRecentFiles->setModel(recentfilesmodel);

    connect(ui->lvRecentFiles, &QListView::clicked, this, &WelcomeTab::onFileSelected);
    connect(ui->pbOpen, &QPushButton::clicked, DisassemblerHooks::instance(), &DisassemblerHooks::open);
    connect(ui->pbSettings, &QPushButton::clicked, DisassemblerHooks::instance(), &DisassemblerHooks::settings);
    connect(ui->pbAbout, &QPushButton::clicked, DisassemblerHooks::instance(), &DisassemblerHooks::about);

    connect(ui->pbREDasmIO, &QPushButton::clicked, this, []() {
        QDesktopServices::openUrl(QUrl("https://redasm.io"));
    });

    connect(ui->pbTelegram, &QPushButton::clicked, this, []() {
        QDesktopServices::openUrl(QUrl("https://redasm.io/telegram"));
    });

    connect(ui->pbReddit, &QPushButton::clicked, this, []() {
        QDesktopServices::openUrl(QUrl("https://redasm.io/reddit"));
    });

    connect(ui->pbGitHub, &QPushButton::clicked, this, []() {
        QDesktopServices::openUrl(QUrl("https://github.com/REDasmOrg/REDasm/issues"));
    });
}

WelcomeTab::~WelcomeTab() { delete ui; }

void WelcomeTab::styleSocialButton(QPushButton* button, const QIcon& icon) const
{
    static QString socialstylesheet = QString("QPushButton {"
                                                  "text-align: left;"
                                              "}");

    button->setFlat(true);
    button->setCursor(Qt::PointingHandCursor);
    button->setStyleSheet(socialstylesheet);
    button->setIconSize({ 28, 28 });
    button->setIcon(icon);
}

void WelcomeTab::onFileSelected(const QModelIndex& index)
{
    const RecentFilesModel* recentfilesmodel = static_cast<const RecentFilesModel*>(index.model());
    DisassemblerHooks::instance()->load(recentfilesmodel->filePath(index));
}
