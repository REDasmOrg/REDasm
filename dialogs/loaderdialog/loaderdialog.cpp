#include "loaderdialog.h"
#include "ui_loaderdialog.h"
#include <redasm/plugins/loader/loader.h>
#include <redasm/context.h>
#include <QPushButton>

LoaderDialog::LoaderDialog(const REDasm::LoadRequest *request, QWidget *parent) : QDialog(parent), ui(new Ui::LoaderDialog), m_request(request)
{
    ui->setupUi(this);

    m_loaders = r_pm->getLoaders(request);
    m_loadersmodel = new QStandardItemModel(ui->lvLoaders);

    for(const auto& entry : m_loaders)
        m_loadersmodel->appendRow(new QStandardItem(QString::fromUtf8(entry->descriptor->description)));

    ui->lvLoaders->setModel(m_loadersmodel);
    ui->lvLoaders->setCurrentIndex(m_loadersmodel->index(0, 0));

    this->populateAssemblers();
    this->checkFlags();
    this->updateInputMask();

    connect(ui->leBaseAddress, &QLineEdit::textEdited, this, [&](const QString&)  {
        this->validateInput();
    });

    connect(ui->leEntryPoint, &QLineEdit::textEdited, this, [&](const QString&)  {
        this->validateInput();
    });

    connect(ui->leOffset, &QLineEdit::textEdited, this, [&](const QString&)  {
        this->validateInput();
    });

    connect(ui->lvLoaders, &QListView::clicked, this, [&](const QModelIndex& index) {
        this->checkFlags();
        this->validateInput();
    });
}

LoaderDialog::~LoaderDialog()
{
    auto ait = std::find(m_assemblers.begin(), m_assemblers.end(), this->selectedAssembler());
    auto lit = std::find(m_loaders.begin(), m_loaders.end(), this->selectedLoader());

    // Keep selected assemblers/loaders
    m_assemblers.erase(ait);
    m_loaders.erase(lit);

    r_pm->unload(m_assemblers);
    r_pm->unload(m_loaders);

    delete ui;
}

const REDasm::PluginInstance *LoaderDialog::selectedLoader() const
{
    QModelIndex index = ui->lvLoaders->currentIndex();

    if(!index.isValid())
        return nullptr;

    return m_loaders[index.row()];
}

const REDasm::PluginInstance* LoaderDialog::selectedAssembler() const
{
    REDasm::LoaderFlags flags = this->selectedLoaderFlags();

    if(flags & REDasm::LoaderFlags::CustomAssembler)
         return r_pm->findAssembler(ui->cbAssembler->currentData().toString().toStdString());

    return nullptr;
}

address_t LoaderDialog::baseAddress() const { return ui->leBaseAddress->text().toULongLong(nullptr, 16); }
address_t LoaderDialog::entryPoint() const { return ui->leEntryPoint->text().toULongLong(nullptr, 16); }
offset_t LoaderDialog::offset() const { return ui->leOffset->text().toULongLong(nullptr, 16); }

REDasm::LoaderFlags LoaderDialog::selectedLoaderFlags() const
{
    QModelIndex index = ui->lvLoaders->currentIndex();

    if(!index.isValid())
        return REDasm::LoaderFlags::None;

    const REDasm::PluginInstance* pi = m_loaders[index.row()];
    return REDasm::plugin_cast<REDasm::Loader>(pi)->flags();
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

    REDasm::LoaderFlags flags = this->selectedLoaderFlags();
    ui->cbAssembler->setEnabled(flags & REDasm::LoaderFlags::CustomAssembler);
    ui->groupBox->setEnabled(flags & REDasm::LoaderFlags::CustomAddressing);
    ui->buttonBox->button(QDialogButtonBox::Ok)->setEnabled(true);
}

void LoaderDialog::validateInput()
{
    bool okenabled = true;
    REDasm::LoaderFlags flags = this->selectedLoaderFlags();

    if(flags & REDasm::LoaderFlags::CustomAddressing)
    {
        if(ui->leOffset->text().isEmpty() || (this->offset() >= m_request->buffer()->size()))
            okenabled = false;
        if((ui->leEntryPoint->text().isEmpty() || ui->leBaseAddress->text().isEmpty()) || (this->entryPoint() > this->baseAddress()))
            okenabled = false;
    }

    ui->buttonBox->button(QDialogButtonBox::Ok)->setEnabled(okenabled);
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
    m_assemblers = r_pm->getAssemblers();

    for(auto it = m_assemblers.begin(); it != m_assemblers.end(); it++)
        ui->cbAssembler->addItem(QString::fromUtf8((*it)->descriptor->description), QString::fromUtf8((*it)->descriptor->id));
}
