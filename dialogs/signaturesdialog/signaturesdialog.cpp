#include "signaturesdialog.h"
#include "ui_signaturesdialog.h"
#include <QFileDialog>
#include <QMessageBox>
#include <redasm/context.h>

SignaturesDialog::SignaturesDialog(REDasm::Disassembler *disassembler, QWidget *parent) : QDialog(parent), ui(new Ui::SignaturesDialog), m_disassembler(disassembler)
{
    ui->setupUi(this);
    ui->leFilter->setEnabled(false);
    ui->pbLoad->setEnabled(false);
    ui->splitter->setStretchFactor(1, 1);

    m_signaturefilesmodel = new SignatureFilesModel(disassembler, this);
    m_signaturesmodel = new SignaturesModel(this);

    ui->tvFiles->setModel(m_signaturefilesmodel);
    ui->tvFiles->verticalHeader()->setDefaultSectionSize(ui->tvFiles->verticalHeader()->minimumSectionSize());
    ui->tvFiles->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);

    m_filtermodel = new QSortFilterProxyModel(this);
    m_filtermodel->setSourceModel(m_signaturesmodel);
    m_filtermodel->setFilterKeyColumn(0);

    ui->tvSignatures->setModel(m_filtermodel);
    ui->tvSignatures->verticalHeader()->setDefaultSectionSize(ui->tvSignatures->verticalHeader()->minimumSectionSize());
    ui->tvSignatures->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);

    connect(ui->tvFiles, &QTableView::clicked, this, &SignaturesDialog::readSignature);
    connect(ui->pbLoad, &QPushButton::clicked, this, &SignaturesDialog::loadSignature);
    connect(ui->pbBrowse, &QPushButton::clicked, this, &SignaturesDialog::browseSignatures);
    connect(ui->leFilter, &QLineEdit::textChanged, m_filtermodel, &QSortFilterProxyModel::setFilterFixedString);

}

SignaturesDialog::~SignaturesDialog() { delete ui; }

void SignaturesDialog::loadSignature(bool)
{
    const std::string& sigpath = m_signaturefilesmodel->signaturePath(ui->tvFiles->currentIndex());

    if(m_disassembler->loadSignature(sigpath))
    {
        m_signaturefilesmodel->mark(ui->tvFiles->currentIndex());
        return;
    }

    QMessageBox msgbox(this);
    msgbox.setWindowTitle("Load Error");
    msgbox.setText(QString("Error loading '%1'").arg(QFileInfo(QString::fromStdString(sigpath)).fileName()));
    msgbox.setStandardButtons(QMessageBox::Ok);
}

void SignaturesDialog::readSignature(const QModelIndex &index)
{
    ui->leFilter->clear();
    ui->leFilter->setEnabled(true);
    ui->pbLoad->setEnabled(!m_signaturefilesmodel->isLoaded(index));
    m_signaturesmodel->setSignature(m_signaturefilesmodel->load(index));
}

void SignaturesDialog::browseSignatures()
{
    QString s = QFileDialog::getOpenFileName(this, "Load Signature...",
                                             QString::fromStdString(r_ctx->signature(std::string())),
                                             "REDasm Signature (*.json)");

    if(s.isEmpty())
        return;

    std::string sigid = QFileInfo(s).baseName().toStdString();

    if(m_signaturefilesmodel->contains(sigid))
        return;

    m_signaturefilesmodel->add(sigid, s.toStdString());
}
