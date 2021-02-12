#include "loaderdialog.h"
#include "ui_loaderdialog.h"
#include <QPushButton>

LoaderDialog::LoaderDialog(RDContextPtr& ctx, const RDLoaderRequest* req, QWidget *parent) : QDialog(parent), ui(new Ui::LoaderDialog), m_request(req)
{
    ui->setupUi(this);
    ui->sbMinString->setValue(static_cast<int>(RDContext_GetMinString(ctx.get())));

    RDContext_FindLoaderEntries(ctx.get(), req,[](const RDEntryLoader* entryloader, void* userdata) {
        LoaderDialog* thethis = reinterpret_cast<LoaderDialog*>(userdata);
        thethis->m_loaders.push_back(entryloader);
    }, this);

    m_loadersmodel = new QStandardItemModel(ui->lvLoaders);

    for(const RDEntryLoader* d : m_loaders)
        m_loadersmodel->appendRow(new QStandardItem(d->name));

    ui->lvLoaders->setModel(m_loadersmodel);
    ui->lvLoaders->setCurrentIndex(m_loadersmodel->index(0, 0));

    this->populateAssemblerEntries(ctx);
    this->checkFlags();
    this->updateInputMask();
    this->syncAssemblerEntry(ctx);
    this->validateFields();

    connect(ui->leBaseAddress, &QLineEdit::textEdited, this, [&](const QString&) { this->validateFields(); });
    connect(ui->leEntryPoint, &QLineEdit::textEdited, this, [&](const QString&)  { this->validateFields(); });
    connect(ui->leOffset, &QLineEdit::textEdited, this, [&](const QString&)  { this->validateFields(); });
    connect(ui->cbAssembler, qOverload<int>(&QComboBox::currentIndexChanged), this, [&](int) { this->validateFields(); });

    connect(ui->lvLoaders, &QListView::clicked, this, [=](const QModelIndex&) {
        this->checkFlags();
        this->syncAssemblerEntry(ctx);
        this->validateFields();
    });

}

LoaderDialog::~LoaderDialog() { delete ui; }
RDLoaderBuildParams LoaderDialog::buildRequest() const { return { this->offset(), this->baseAddress(), this->entryPoint() }; }

const RDEntryLoader *LoaderDialog::selectedLoaderEntry() const
{
    QModelIndex index = ui->lvLoaders->currentIndex();
    if(!index.isValid()) return nullptr;
    return m_loaders.at(index.row());
}

const RDEntryAssembler* LoaderDialog::selectedAssemblerEntry() const
{
    size_t idx = static_cast<size_t>(ui->cbAssembler->currentIndex());
    return (idx > 0) && (idx < m_assemblers.size()) ? m_assemblers.at(ui->cbAssembler->currentIndex()) : nullptr;
}

size_t LoaderDialog::selectedMinString() const { return static_cast<size_t>(ui->sbMinString->value()); }
rd_address LoaderDialog::baseAddress() const { return ui->leBaseAddress->text().toULongLong(nullptr, 16); }
rd_address LoaderDialog::entryPoint() const { return ui->leEntryPoint->text().toULongLong(nullptr, 16); }
rd_offset LoaderDialog::offset() const { return ui->leOffset->text().toULongLong(nullptr, 16); }

rd_flag LoaderDialog::selectedLoaderFlags() const
{
    QModelIndex index = ui->lvLoaders->currentIndex();
    return index.isValid() ? m_loaders[index.row()]->flags : LoaderFlags_None;
}

void LoaderDialog::checkFlags()
{
    QModelIndex index = ui->lvLoaders->currentIndex();

    if(!index.isValid())
    {
        ui->cbAssembler->setEnabled(false);
        ui->widgetAddressing->setEnabled(false);
        ui->buttonBox->button(QDialogButtonBox::Ok)->setEnabled(false);
        return;
    }

    rd_flag flags = this->selectedLoaderFlags();
    ui->cbAssembler->setEnabled(flags & LoaderFlags_CustomAssembler);
    ui->widgetAddressing->setEnabled(flags & LoaderFlags_CustomAddressing);
    ui->buttonBox->button(QDialogButtonBox::Ok)->setEnabled(true);
}

void LoaderDialog::validateFields()
{
    bool okenabled = ui->sbMinString->value() > 0;
    rd_flag flags = this->selectedLoaderFlags();

    if(flags & LoaderFlags_CustomAddressing)
    {
        if(ui->leOffset->text().isEmpty() || (this->offset() >= RDBuffer_Size(m_request->buffer)))
            okenabled = false;
        if((ui->leEntryPoint->text().isEmpty() || ui->leBaseAddress->text().isEmpty()) || (this->entryPoint() > this->baseAddress()))
            okenabled = false;
    }

    ui->buttonBox->button(QDialogButtonBox::Ok)->setEnabled(okenabled && (ui->cbAssembler->currentIndex() > 0));
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

void LoaderDialog::syncAssemblerEntry(const RDContextPtr& ctx)
{
    const RDEntryLoader* entryloader = this->selectedLoaderEntry();
    if(!entryloader) return;

    const RDEntryAssembler* entryassembler = RDContext_FindAssemblerEntry(ctx.get(), entryloader);
    if(entryassembler) ui->cbAssembler->setCurrentText(entryassembler->name);
    else ui->cbAssembler->setCurrentIndex(-1);
}

void LoaderDialog::populateAssemblerEntries(const RDContextPtr& ctx)
{
    ui->cbAssembler->addItem(QString()); // Empty placeholder
    m_assemblers.push_back(nullptr);     // Dummy assembler

    RDContext_FindAssemblerEntries(ctx.get(), [](const RDEntryAssembler* entry, void* userdata) {
        LoaderDialog* thethis = reinterpret_cast<LoaderDialog*>(userdata);
        thethis->m_assemblers.push_back(entry);
        thethis->ui->cbAssembler->addItem(entry->name, entry->id);
    }, this);
}
