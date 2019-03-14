#include "formatloaderdialog.h"
#include "ui_formatloaderdialog.h"
#include <QPushButton>
#include <QListView>

FormatLoaderDialog::FormatLoaderDialog(const QString &ext, REDasm::LoaderEntryListByExt *loaders, QWidget *parent) : QDialog(parent), ui(new Ui::FormatLoaderDialog), m_loaders(loaders), m_discarded(false)
{
    ui->setupUi(this);

    m_loadersmodel = new QStandardItemModel(ui->lvFormats);
    ui->lvFormats->setModel(m_loadersmodel);

    ui->lblInfo->setText(QString("REDasm detected valid loaders for the extension '%1', in this case you can:\n"
                                 "- Select 'Discard' to continue the classic loading procedure.\n"
                                 "- Select a loader from the list below.").arg(ext));

    ui->buttonBox->button(QDialogButtonBox::Ok)->setEnabled(false);

    connect(ui->buttonBox, &QDialogButtonBox::accepted, this, &FormatLoaderDialog::accept);
    connect(ui->buttonBox, &QDialogButtonBox::rejected, this, &FormatLoaderDialog::reject);

    connect(ui->buttonBox->button(QDialogButtonBox::Discard), &QPushButton::clicked, this, [&]() {
        m_discarded = true;
        this->accept();
    });

    connect(ui->lvFormats, &QListView::clicked, this, [&](const QModelIndex& index) {
        ui->buttonBox->button(QDialogButtonBox::Ok)->setEnabled(index.isValid());
    });

    this->loadFormats();
}

FormatLoaderDialog::~FormatLoaderDialog() { delete ui; }
bool FormatLoaderDialog::discarded() const { return m_discarded; }

REDasm::LoaderPlugin *FormatLoaderDialog::loadSelectedLoader(REDasm::AbstractBuffer *buffer)
{
    QItemSelectionModel* selectionmodel = ui->lvFormats->selectionModel();

    if(!selectionmodel->hasSelection())
        return nullptr;

    QModelIndex index = selectionmodel->currentIndex();

    if(!index.isValid() || (index.row() >= m_loaders->size()))
        return nullptr;

    return m_loaders->at(index.row()).first(buffer);
}

void FormatLoaderDialog::loadFormats()
{
    for(auto it = m_loaders->begin(); it != m_loaders->end(); it++)
        m_loadersmodel->appendRow(new QStandardItem(QString::fromStdString(it->second)));
}
