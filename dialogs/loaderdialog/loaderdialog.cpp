#include "loaderdialog.h"
#include "ui_loaderdialog.h"
#include "../convert.h"
#include <redasm/plugins/loader/loader.h>
#include <redasm/context.h>
#include <QPushButton>

LoaderDialog::LoaderDialog(const REDasm::LoadRequest& request, QWidget *parent) : QDialog(parent), ui(new Ui::LoaderDialog), m_request(request)
{
    ui->setupUi(this);

    m_loaders = r_pm->getLoaders(request);
    m_loadersmodel = new QStandardItemModel(ui->lvLoaders);

    for(size_t i = 0; i < m_loaders.size(); i++)
    {
        const REDasm::PluginInstance* pi = m_loaders.at(i);
        m_loadersmodel->appendRow(new QStandardItem(Convert::to_qstring(pi->descriptor->description)));
    }

    ui->lvLoaders->setModel(m_loadersmodel);
    ui->lvLoaders->setCurrentIndex(m_loadersmodel->index(0, 0));

    this->populateAssemblers();
    this->checkFlags();
    this->updateInputMask();
    this->syncAssembler();

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
        this->syncAssembler();
    });
}

LoaderDialog::~LoaderDialog()
{
    if(!m_assemblers.empty() && this->selectedAssembler())
    {
        m_assemblers.erase(this->selectedLoader()); // Keep selected assembler
        r_pm->unload(m_assemblers);
    }

    if(!m_loaders.empty())
    {
        m_loaders.erase(this->selectedLoader());   // Keep selected loader
        r_pm->unload(m_loaders);
    }

    delete ui;
}

const REDasm::PluginInstance *LoaderDialog::selectedLoader() const
{
    QModelIndex index = ui->lvLoaders->currentIndex();

    if(!index.isValid())
        return nullptr;

    return m_loaders.at(index.row());
}

const REDasm::PluginInstance* LoaderDialog::selectedAssembler() const
{
    REDasm::LoaderFlags flags = this->selectedLoaderFlags();

    if(flags & REDasm::LoaderFlags::CustomAssembler)
        return m_assemblers.at(ui->cbAssembler->currentIndex());

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

    const REDasm::PluginInstance* pi = m_loaders.at(index.row());
    return plugin_cast<REDasm::Loader>(pi)->flags();
}

void LoaderDialog::checkFlags()
{
    QModelIndex index = ui->lvLoaders->currentIndex();

    if(!index.isValid())
    {
        ui->cbAssembler->setEnabled(false);
        ui->tabAddressing->setEnabled(false);
        ui->buttonBox->button(QDialogButtonBox::Ok)->setEnabled(false);
        return;
    }

    REDasm::LoaderFlags flags = this->selectedLoaderFlags();
    ui->cbAssembler->setEnabled(flags & REDasm::LoaderFlags::CustomAssembler);
    ui->tabAddressing->setEnabled(flags & REDasm::LoaderFlags::CustomAddressing);
    ui->buttonBox->button(QDialogButtonBox::Ok)->setEnabled(true);
}

void LoaderDialog::validateInput()
{
    bool okenabled = true;
    REDasm::LoaderFlags flags = this->selectedLoaderFlags();

    if(flags & REDasm::LoaderFlags::CustomAddressing)
    {
        if(ui->leOffset->text().isEmpty() || (this->offset() >= m_request.buffer()->size()))
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

void LoaderDialog::syncAssembler()
{
    const REDasm::PluginInstance* pi = this->selectedLoader();

    if(!pi)
        return;

    auto* loader = plugin_cast<REDasm::Loader>(pi);

    for(size_t i = 0; i < m_assemblers.size(); i++)
    {
        if(loader->assembler().id != m_assemblers.at(i)->descriptor->id)
            continue;

        ui->cbAssembler->setCurrentText(Convert::to_qstring(m_assemblers.at(i)->descriptor->description));
        break;
    }
}

void LoaderDialog::populateAssemblers()
{
    m_assemblers = r_pm->getAssemblers();

    for(size_t i = 0; i < m_assemblers.size(); i++)
    {
        const REDasm::PluginInstance* pi = m_assemblers.at(i);
        ui->cbAssembler->addItem(Convert::to_qstring(pi->descriptor->description), Convert::to_qstring(pi->descriptor->id));
    }
}

void LoaderDialog::accept()
{
    r_ctx->flag(REDasm::ContextFlags::StepDisassembly, ui->chbStepDisassembly->isChecked());
    QDialog::accept();
}
