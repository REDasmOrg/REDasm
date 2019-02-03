#include "settingsdialog.h"
#include "ui_settingsdialog.h"
#include "../themeprovider.h"
#include "../redasmsettings.h"

SettingsDialog::SettingsDialog(QWidget *parent): QDialog(parent), ui(new Ui::SettingsDialog)
{
    ui->setupUi(this);
    ui->cbTheme->addItems(ThemeProvider::themes());
    this->selectCurrentTheme();

    connect(this, &QDialog::accepted, this, &SettingsDialog::onAccepted);
}

SettingsDialog::~SettingsDialog() { delete ui; }

void SettingsDialog::selectCurrentTheme()
{
    REDasmSettings settings;

    for(int i = 0; i < ui->cbTheme->count(); i++)
    {
        if(QString::compare(ui->cbTheme->itemText(i), settings.currentTheme(), Qt::CaseInsensitive))
            continue;

        ui->cbTheme->setCurrentIndex(i);
        break;
    }
}

void SettingsDialog::onAccepted()
{
    REDasmSettings settings;
    settings.changeTheme(ui->cbTheme->currentText());
}
