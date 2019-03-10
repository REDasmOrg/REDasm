#include "manualloaddialog.h"
#include "ui_manualloaddialog.h"
#include <redasm/formats/binary/binary.h>

ManualLoadDialog::ManualLoadDialog(REDasm::FormatPlugin *format, QWidget *parent) : QDialog(parent), ui(new Ui::ManualLoadDialog), m_format(format)
{
    ui->setupUi(this);
    this->loadBits();
    this->loadAssemblers();
    this->updateInputMask();

    connect(ui->cbBits, static_cast<void(QComboBox::*)(int)>(&QComboBox::currentIndexChanged), this, [&](int) { this->updateInputMask(); });
}

ManualLoadDialog::~ManualLoadDialog()
{
    delete ui;
}

void ManualLoadDialog::initText()
{
    u32 bits = ui->cbBits->currentData().toUInt();
    s32 maxlen = bits / 4;
    QString initval = QString("0").repeated(maxlen);

    ui->leEntryPoint->setText(initval);
    ui->leOffset->setText(initval);
    ui->leBaseAddress->setText(initval);
}

void ManualLoadDialog::loadBits()
{
    ui->cbBits->addItem("8", 8);
    ui->cbBits->addItem("16", 16);
    ui->cbBits->addItem("32", 32);
    ui->cbBits->addItem("64", 64);
    ui->cbBits->setCurrentIndex(2);
}

void ManualLoadDialog::loadAssemblers()
{
    std::for_each(REDasm::Plugins::assemblers.begin(), REDasm::Plugins::assemblers.end(), [this](const std::pair<std::string, REDasm::AssemblerPlugin_Entry>& item) {
        ui->cbAssemblers->addItem(QString::fromStdString(item.first));
    });
}

void ManualLoadDialog::updateInputMask()
{
    u32 bits = ui->cbBits->currentData().toUInt();
    u32 maxlen = bits / 4;
    QString mask = "H" + QString("h").repeated(maxlen - 1);

    ui->leEntryPoint->setInputMask(mask);
    ui->leOffset->setInputMask(mask);
    ui->leBaseAddress->setInputMask(mask);
    this->initText();
}

void ManualLoadDialog::on_buttonBox_accepted()
{
    REDasm::BinaryFormat* binaryformat = dynamic_cast<REDasm::BinaryFormat*>(m_format);

    binaryformat->build(ui->cbAssemblers->currentText().toStdString(),
                        ui->cbBits->currentData().toInt(),
                        ui->leOffset->text().toULongLong(NULL, 16),
                        ui->leBaseAddress->text().toULongLong(NULL, 16),
                        ui->leEntryPoint->text().toULongLong(NULL, 16));
}
