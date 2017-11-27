#include "gotodialog.h"
#include "ui_gotodialog.h"

GotoDialog::GotoDialog(REDasm::Disassembler *disassembler, QWidget *parent) : QDialog(parent), ui(new Ui::GotoDialog), _disassembler(disassembler), _address(0)
{
    ui->setupUi(this);

    this->_functionsmodel = new SymbolTableFilterModel(ui->tvFunctions);
    this->_functionsmodel->setFilterSymbol(REDasm::SymbolTypes::FunctionMask);
    this->_functionsmodel->setDisassembler(disassembler);

    ui->tvFunctions->setModel(this->_functionsmodel);
    ui->tvFunctions->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    ui->tvFunctions->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);

    connect(ui->leAddress, &QLineEdit::textChanged, [this](const QString) { this->validateEntry(); });
    connect(ui->leAddress, &QLineEdit::returnPressed, this, &GotoDialog::accept);

    connect(ui->tvFunctions, &QTableView::doubleClicked, this, &GotoDialog::symbolSelected);
    connect(ui->tvFunctions, &QTableView::doubleClicked, this, &GotoDialog::accept);
}

address_t GotoDialog::address() const
{
    return this->_address;
}

GotoDialog::~GotoDialog()
{
    delete ui;
}

void GotoDialog::validateEntry()
{
    bool ok = false;
    QString s = ui->leAddress->text();

    if(s.isEmpty())
    {
        ui->pbGoto->setEnabled(false);
        this->_functionsmodel->setFilterName(QString());
        return;
    }

    this->_address = s.toULongLong(&ok, 16);
    ui->pbGoto->setEnabled(ok);

    this->_functionsmodel->setFilterName(s);
}
