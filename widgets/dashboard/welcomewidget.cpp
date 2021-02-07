#include "welcomewidget.h"
#include "ui_welcomewidget.h"
#include "../../delegates/recentfilesdelegate.h"
#include "../../models/recentfilesmodel.h"
#include "../../hooks/disassemblerhooks.h"
#include "../../redasmsettings.h"
#include "../../redasmfonts.h"
#include <QFileInfo>

WelcomeWidget::WelcomeWidget(QWidget *parent) : DashboardWidget(parent), ui(new Ui::WelcomeWidget)
{
    DisassemblerHooks::instance()->setTabBarVisible(false);

    ui->setupUi(this);
    this->setWindowTitle("Welcome");
    this->applyLogo(ui->lblBrand);

    ui->lblVersion->setText(QString("Version %1").arg(REDASM_VERSION));
    ui->lvRecentFiles->viewport()->setAttribute(Qt::WA_Hover);
    ui->lvRecentFiles->viewport()->setBackgroundRole(QPalette::Window);

    ui->pbOpen->setCursor(Qt::PointingHandCursor);
    ui->pbSettings->setCursor(Qt::PointingHandCursor);
    ui->pbAbout->setCursor(Qt::PointingHandCursor);
    this->makeBordered(ui->pbOpen);
    this->makeBordered(ui->pbSettings);
    this->makeBordered(ui->pbAbout);

    this->styleSocialButton(ui->pbREDasmIO, FA_ICON(0xf015));
    this->styleSocialButton(ui->pbTwitter,  FAB_ICON(0xf099));
    this->styleSocialButton(ui->pbTelegram, FAB_ICON(0xf3fe));
    this->styleSocialButton(ui->pbReddit,   FAB_ICON(0xf281));
    this->styleSocialButton(ui->pbGitHub,   FAB_ICON(0xf113));

    RecentFilesModel* recentfilesmodel = new RecentFilesModel(ui->lvRecentFiles);
    recentfilesmodel->update();

    ui->lvRecentFiles->setItemDelegate(new RecentFilesDelegate(ui->lvRecentFiles));
    ui->lvRecentFiles->setModel(recentfilesmodel);

    connect(ui->lvRecentFiles, &QListView::clicked, this, &WelcomeWidget::onFileSelected);
    connect(ui->pbOpen, &QPushButton::clicked, DisassemblerHooks::instance(), &DisassemblerHooks::open);
    connect(ui->pbSettings, &QPushButton::clicked, DisassemblerHooks::instance(), &DisassemblerHooks::settings);
    connect(ui->pbAbout, &QPushButton::clicked, DisassemblerHooks::instance(), &DisassemblerHooks::about);
    connect(ui->pbREDasmIO, &QPushButton::clicked, this, []() { DisassemblerHooks::instance()->openHomePage(); });
    connect(ui->pbTwitter, &QPushButton::clicked, this, []() { DisassemblerHooks::instance()->openTwitter(); });
    connect(ui->pbTelegram, &QPushButton::clicked, this, []() { DisassemblerHooks::instance()->openTelegram(); });
    connect(ui->pbReddit, &QPushButton::clicked, this, []() { DisassemblerHooks::instance()->openReddit(); });
    connect(ui->pbGitHub, &QPushButton::clicked, this, []() { DisassemblerHooks::instance()->openGitHub(); });
}

WelcomeWidget::~WelcomeWidget() { delete ui; }

void WelcomeWidget::styleSocialButton(QPushButton* button, const QIcon& icon) const
{
    static const QString socialstylesheet = QString("QPushButton {"
                                                        "text-align: left;"
                                                    "}");

    button->setFlat(true);
    button->setCursor(Qt::PointingHandCursor);
    button->setStyleSheet(socialstylesheet);
    button->setIconSize({ 28, 28 });
    button->setIcon(icon);
}

void WelcomeWidget::onFileSelected(const QModelIndex& index)
{
    const RecentFilesModel* recentfilesmodel = static_cast<const RecentFilesModel*>(index.model());
    DisassemblerHooks::instance()->load(recentfilesmodel->filePath(index));
}
