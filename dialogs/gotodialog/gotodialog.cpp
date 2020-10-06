#include "gotodialog.h"
#include "ui_gotodialog.h"

GotoDialog::GotoDialog(ICommand* command, QWidget *parent) : QDialog(parent), ui(new Ui::GotoDialog), m_command(command)
{
    ui->setupUi(this);

    m_document = RDContext_GetDocument(command->context().get());

    m_gotomodel = new GotoFilterModel(ui->tvFunctions);
    m_gotomodel->setDisassembler(command->context());

    ui->tvFunctions->setModel(m_gotomodel);
    ui->tvFunctions->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    ui->tvFunctions->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);

    connect(ui->leAddress, &QLineEdit::textChanged, this, [=](const QString) { this->validateEntry(); });
    connect(ui->leAddress, &QLineEdit::returnPressed, this, &GotoDialog::onGotoClicked);
    connect(ui->tvFunctions, &QTableView::doubleClicked, this, &GotoDialog::onItemSelected);
    connect(ui->tvFunctions, &QTableView::doubleClicked, this, &GotoDialog::accept);
    connect(ui->pbGoto, &QPushButton::clicked, this, &GotoDialog::onGotoClicked);
}

GotoDialog::~GotoDialog() { delete ui; }
bool GotoDialog::hasValidAddress() const { return m_validaddress && RDDocument_GetSegmentAddress(m_document, m_address, nullptr); }

void GotoDialog::validateEntry()
{
    bool ok = false;
    QString s = ui->leAddress->text();

    if(s.isEmpty())
    {
        m_validaddress = false;
        ui->pbGoto->setEnabled(false);
        m_gotomodel->setFilterFixedString(QString());
        return;
    }

    m_address = s.toULongLong(&ok, 16);
    ui->pbGoto->setEnabled(ok);
    m_validaddress = ok;
    m_gotomodel->setFilterFixedString(s);
}

void GotoDialog::onGotoClicked()
{
    if(this->hasValidAddress())
        m_command->gotoAddress(m_address);

    this->accept();
}

void GotoDialog::onItemSelected(const QModelIndex &index)
{
    QModelIndex srcindex = m_gotomodel->mapToSource(index);
    if(!srcindex.isValid()) return;

    RDDocumentItem item;
    if(!RDDocument_GetItemAt(m_document, srcindex.row(), &item)) return;
    m_command->gotoItem(item);
}
