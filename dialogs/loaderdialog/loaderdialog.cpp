#include "loaderdialog.h"
#include "ui_loaderdialog.h"
#include <QPushButton>

LoaderDialog::LoaderDialog(const REDasm::LoaderList &loaders, QWidget *parent) : QDialog(parent), m_loaders(loaders), ui(new Ui::LoaderDialog)
{
    ui->setupUi(this);
    m_loadersmodel = new QStandardItemModel(ui->lvLoaders);

    for(const auto& entry : m_loaders)
        m_loadersmodel->appendRow(new QStandardItem(QString::fromStdString(entry->name())));

    ui->lvLoaders->setModel(m_loadersmodel);
    ui->lvLoaders->setCurrentIndex(m_loadersmodel->index(0, 0));

    this->populateAssemblers();
    this->checkFlags();
    this->updateInputMask();

    connect(ui->lvLoaders, &QListView::clicked, this, [&](const QModelIndex& index) {
        this->checkFlags();
    });
}

const REDasm::LoaderPlugin_Entry* LoaderDialog::selectedLoader() const
{
    QModelIndex index = ui->lvLoaders->currentIndex();

    if(!index.isValid())
        return nullptr;

    return m_loaders[index.row()];
}

const REDasm::AssemblerPlugin_Entry* LoaderDialog::selectedAssembler() const
{
    u32 flags = this->selectedLoaderFlags();

    if(flags & REDasm::LoaderFlags::CustomAssembler)
        return REDasm::getAssembler(ui->cbAssembler->currentData().toString().toStdString());

    return nullptr;
}

address_t LoaderDialog::baseAddress() const { return ui->leBaseAddress->text().toULongLong(); }
address_t LoaderDialog::entryPoint() const { return ui->leEntryPoint->text().toULongLong(); }
offset_t LoaderDialog::offset() const { return ui->leOffset->text().toULongLong(); }
LoaderDialog::~LoaderDialog() { delete ui; }

u32 LoaderDialog::selectedLoaderFlags() const
{
    QModelIndex index = ui->lvLoaders->currentIndex();

    if(!index.isValid())
        return REDasm::LoaderFlags::None;

    const auto* loaderentry = m_loaders[index.row()];
    return loaderentry->flags();
}

void LoaderDialog::checkFlags()
{
    QModelIndex index = ui->lvLoaders->currentIndex();

    if(!index.isValid())
    {
        ui->cbAssembler->setEnabled(false);
        ui->groupBox->setEnabled(false);
        ui->buttonBox->button(QDialogButtonBox::Ok)->setEnabled(false);
        return;
    }

    u32 flags = this->selectedLoaderFlags();
    ui->cbAssembler->setEnabled(flags & REDasm::LoaderFlags::CustomAssembler);
    ui->groupBox->setEnabled(flags & REDasm::LoaderFlags::CustomAddressing);
    ui->buttonBox->button(QDialogButtonBox::Ok)->setEnabled(true);
}

void LoaderDialog::updateInputMask()
{
    QString mask = "H" + QString("h").repeated(16);
    ui->leEntryPoint->setInputMask(mask);
    ui->leOffset->setInputMask(mask);
    ui->leBaseAddress->setInputMask(mask);

    ui->leEntryPoint->setText(QString("0").repeated(16));
    ui->leOffset->setText(QString("0").repeated(16));
    ui->leBaseAddress->setText(QString("0").repeated(16));
}

void LoaderDialog::populateAssemblers()
{
    const auto& assemblers = REDasm::Plugins::assemblers;

    for(auto it = assemblers.begin(); it != assemblers.end(); it++)
        ui->cbAssembler->addItem(QString::fromStdString(it->second.name()), QString::fromStdString(it->first));
}
