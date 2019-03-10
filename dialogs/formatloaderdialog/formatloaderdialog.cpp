#include "formatloaderdialog.h"
#include "ui_formatloaderdialog.h"
#include <QPushButton>
#include <QListView>

FormatLoaderDialog::FormatLoaderDialog(const QString &ext, REDasm::FormatEntryListByExt *formats, QWidget *parent) : QDialog(parent), ui(new Ui::FormatLoaderDialog), m_formats(formats), m_discarded(false)
{
    ui->setupUi(this);

    m_formatsmodel = new QStandardItemModel(ui->lvFormats);
    ui->lvFormats->setModel(m_formatsmodel);

    ui->lblInfo->setText(QString("REDasm detected valid loaders for the extension '%1', in this case you can:\n"
                                 "- Select 'Discard' to continue the classic loading procedure.\n"
                                 "- Select a format from the list below").arg(ext));

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

REDasm::FormatPlugin *FormatLoaderDialog::loadSelectedFormat(REDasm::AbstractBuffer *buffer)
{
    QItemSelectionModel* selectionmodel = ui->lvFormats->selectionModel();

    if(!selectionmodel->hasSelection())
        return nullptr;

    QModelIndex index = selectionmodel->currentIndex();

    if(!index.isValid() || (index.row() >= m_formats->size()))
        return nullptr;

    return m_formats->at(index.row()).first(buffer);
}

void FormatLoaderDialog::loadFormats()
{
    for(auto it = m_formats->begin(); it != m_formats->end(); it++)
        m_formatsmodel->appendRow(new QStandardItem(QString::fromStdString(it->second)));
}
