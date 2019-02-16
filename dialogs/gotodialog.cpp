#include "gotodialog.h"
#include "ui_gotodialog.h"

GotoDialog::GotoDialog(REDasm::DisassemblerAPI *disassembler, QWidget *parent) : QDialog(parent), ui(new Ui::GotoDialog), m_disassembler(disassembler), m_address(0)
{
    ui->setupUi(this);

    m_functionsmodel = ListingFilterModel::createFilter<ListingItemModel>(REDasm::ListingItem::FunctionItem, ui->tvFunctions);
    m_functionsmodel->setDisassembler(disassembler);

    ui->tvFunctions->setModel(m_functionsmodel);
    ui->tvFunctions->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    ui->tvFunctions->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);

    connect(ui->leAddress, &QLineEdit::textChanged, this, [=](const QString) { this->validateEntry(); });
    connect(ui->leAddress, &QLineEdit::returnPressed, this, &GotoDialog::accept);

    connect(ui->tvFunctions, &QTableView::doubleClicked, this, &GotoDialog::symbolSelected);
    connect(ui->tvFunctions, &QTableView::doubleClicked, this, &GotoDialog::accept);
}

GotoDialog::~GotoDialog() { delete ui; }
address_t GotoDialog::address() const { return m_address; }

void GotoDialog::validateEntry()
{
    bool ok = false;
    QString s = ui->leAddress->text();

    if(s.isEmpty())
    {
        ui->pbGoto->setEnabled(false);
        m_functionsmodel->clearFilter();
        return;
    }

    m_address = s.toULongLong(&ok, 16);
    ui->pbGoto->setEnabled(ok);
    m_functionsmodel->setFilter(s);
}
