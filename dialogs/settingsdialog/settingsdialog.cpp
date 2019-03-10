#include "settingsdialog.h"
#include "ui_settingsdialog.h"
#include "../../themeprovider.h"
#include "../../redasmsettings.h"
#include <QMessageBox>

SettingsDialog::SettingsDialog(QWidget *parent): QDialog(parent), ui(new Ui::SettingsDialog)
{
    ui->setupUi(this);
    ui->cbTheme->addItems(ThemeProvider::themes());
    ui->fcbFonts->setFontFilters(QFontComboBox::MonospacedFonts);

    auto sizes = QFontDatabase::standardSizes();

    for(int size : sizes)
        ui->cbSizes->addItem(QString::number(size), size);

    this->selectCurrentTheme();
    this->selectCurrentFont();
    this->selectCurrentSize();
    this->updatePreview();

    connect(ui->fcbFonts, &QFontComboBox::currentFontChanged, this, [&](const QFont&) { this->updatePreview(); });
    connect(ui->cbSizes, &QComboBox::currentTextChanged, this, [&](const QString&) { this->updatePreview(); });
    connect(ui->pbDefaultFont, &QPushButton::clicked, this, &SettingsDialog::selectDefaultFont);
    connect(this, &QDialog::accepted, this, &SettingsDialog::onAccepted);
}

SettingsDialog::~SettingsDialog() { delete ui; }

void SettingsDialog::selectSize(int size)
{
    for(int i = 0; i < ui->cbSizes->count(); i++)
    {
        if(ui->cbSizes->itemData(i).toInt() != size)
            continue;

        ui->cbSizes->setCurrentIndex(i);
        break;
    }
}

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

void SettingsDialog::selectCurrentFont()
{
    REDasmSettings settings;
    ui->fcbFonts->setCurrentFont(settings.currentFont());
}

void SettingsDialog::selectCurrentSize()
{
    REDasmSettings settings;
    this->selectSize(settings.currentFontSize());
}

void SettingsDialog::updatePreview()
{
    QFont font = ui->fcbFonts->currentFont();
    font.setPixelSize(ui->cbSizes->currentData().toInt());
    ui->lblPreview->setFont(font);
}

void SettingsDialog::selectDefaultFont()
{
    QFont font = QFontDatabase::systemFont(QFontDatabase::FixedFont);
    ui->fcbFonts->setCurrentFont(font);

    int size = qApp->font().pixelSize();

    if(size == -1)
        size = qApp->fontMetrics().height();

    this->selectSize(size);
}

void SettingsDialog::onAccepted()
{
    REDasmSettings settings;
    settings.changeTheme(ui->cbTheme->currentText());
    settings.changeFont(ui->fcbFonts->currentFont());
    settings.changeFontSize(ui->cbSizes->currentData().toInt());

    QMessageBox::information(this, "Settings Applied", "Restart to apply settings");
}
