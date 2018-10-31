#include "settingsdialog.h"
#include "ui_settingsdialog.h"
#include "../redasmsettings.h"
#include <QtDebug>

SettingsDialog::SettingsDialog(QWidget *parent): QDialog(parent), ui(new Ui::SettingsDialog)
{
    ui->setupUi(this);

    ui->cbTheme->addItem("Light", REDasmSettings::Theme::Light);
    ui->cbTheme->addItem("Dark", REDasmSettings::Theme::Dark);

    REDasmSettings settings;
    ui->cbTheme->setCurrentIndex(settings.currentTheme());

    connect(this, &QDialog::accepted, this, &SettingsDialog::onAccepted);
}

SettingsDialog::~SettingsDialog() { delete ui; }

void SettingsDialog::onAccepted()
{
    REDasmSettings settings;
    settings.changeTheme(ui->cbTheme->currentData().toInt());
}
