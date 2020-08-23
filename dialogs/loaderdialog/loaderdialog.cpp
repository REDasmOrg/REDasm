#include "loaderdialog.h"
#include "ui_loaderdialog.h"
#include <QPushButton>

LoaderDialog::LoaderDialog(const RDLoaderRequest* request, QWidget *parent) : QDialog(parent), ui(new Ui::LoaderDialog), m_request(request)
{
    ui->setupUi(this);

    RD_GetLoaders(request, [](RDLoaderPlugin* descriptor, void* userdata) {
        LoaderDialog* thethis = reinterpret_cast<LoaderDialog*>(userdata);
        thethis->m_loaders.push_back(descriptor);
    }, this);

    m_loadersmodel = new QStandardItemModel(ui->lvLoaders);

    for(const RDLoaderPlugin* d : m_loaders)
        m_loadersmodel->appendRow(new QStandardItem(d->name));

    ui->lvLoaders->setModel(m_loadersmodel);
    ui->lvLoaders->setCurrentIndex(m_loadersmodel->index(0, 0));

    this->populateAssemblers();
    this->checkFlags();
    this->updateInputMask();
    this->syncAssembler();

    connect(ui->leBaseAddress, &QLineEdit::textEdited, this, [&](const QString&) { this->validateFields(); });
    connect(ui->leEntryPoint, &QLineEdit::textEdited, this, [&](const QString&)  { this->validateFields(); });
    connect(ui->leOffset, &QLineEdit::textEdited, this, [&](const QString&)  { this->validateFields(); });
    connect(ui->cbAssembler, qOverload<int>(&QComboBox::currentIndexChanged), this, [&](int) { this->validateFields(); });

    connect(ui->lvLoaders, &QListView::clicked, this, [&](const QModelIndex&) {
        this->checkFlags();
        this->syncAssembler();
        this->validateFields();
    });
}

LoaderDialog::~LoaderDialog()
{
    if(!m_assemblers.empty() && this->selectedAssembler())
        m_assemblers.removeOne(this->selectedAssembler()); // Keep selected assembler

    if(!m_loaders.empty())
        m_loaders.removeOne(this->selectedLoader()); // Keep selected loader

    std::for_each(m_loaders.begin(), m_loaders.end(), [](RDLoaderPlugin* plugin) {
        RDPlugin_Free(reinterpret_cast<RDPluginHeader*>(plugin));
    });

    std::for_each(m_assemblers.begin(), m_assemblers.end(), [](RDAssemblerPlugin* plugin) {
        if(plugin) RDPlugin_Free(reinterpret_cast<RDPluginHeader*>(plugin));
    });

    delete ui;
}

RDLoaderBuildRequest LoaderDialog::buildRequest() const { return { this->offset(), this->baseAddress(), this->entryPoint() }; }

RDLoaderPlugin *LoaderDialog::selectedLoader() const
{
    QModelIndex index = ui->lvLoaders->currentIndex();
    if(!index.isValid()) return nullptr;
    return m_loaders.at(index.row());
}

RDAssemblerPlugin* LoaderDialog::selectedAssembler() const
{
    rd_flag flags = this->selectedLoaderFlags();

    if(flags & LoaderFlags_CustomAssembler)
    {
        int idx = ui->cbAssembler->currentIndex();
        return (idx > 0) && (idx < m_assemblers.size()) ? m_assemblers.at(ui->cbAssembler->currentIndex()) : nullptr;
    }

    return RDLoader_GetAssemblerPlugin(this->selectedLoader());
}

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
    bool okenabled = true;
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

void LoaderDialog::syncAssembler()
{
    const RDLoaderPlugin* ploader = this->selectedLoader();
    if(!ploader) return;

    const RDAssemblerPlugin* selassembler = RDLoader_GetAssemblerPlugin(ploader);
    if(selassembler) ui->cbAssembler->setCurrentText(selassembler->name);
    else ui->cbAssembler->setCurrentIndex(-1);
}

void LoaderDialog::populateAssemblers()
{
    ui->cbAssembler->addItem(QString()); // Empty placeholder
    m_assemblers.push_back(nullptr);     // Dummy assembler

    RD_GetAssemblers([](RDAssemblerPlugin* plugin, void* userdata) {
        LoaderDialog* thethis = reinterpret_cast<LoaderDialog*>(userdata);
        thethis->m_assemblers.push_back(plugin);
        thethis->ui->cbAssembler->addItem(plugin->name, plugin->id);
    }, this);
}
