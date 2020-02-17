#include "functiongraphdialog.h"
#include "ui_functiongraphdialog.h"
#include <redasm/disassembler/disassembler.h>
#include <redasm/context.h>

FunctionGraphDialog::FunctionGraphDialog(QWidget *parent) : QDialog(parent), ui(new Ui::FunctionGraphDialog)
{
    ui->setupUi(this);
    ui->splitter->setStretchFactor(1, 1);

    m_functionlistmodel = new FunctionListModel(ui->tbvFunctions);
    m_functiongraphmodel = new FunctionGraphModel(ui->tbvGraph);
    ui->tbvFunctions->setModel(m_functionlistmodel);
    ui->tbvGraph->setModel(m_functiongraphmodel);

    ui->tbvFunctions->verticalHeader()->setDefaultSectionSize(ui->tbvFunctions->verticalHeader()->minimumSectionSize());
    ui->tbvFunctions->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    ui->tbvFunctions->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);

    ui->tbvGraph->verticalHeader()->setDefaultSectionSize(ui->tbvFunctions->verticalHeader()->minimumSectionSize());
    ui->tbvGraph->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);

    connect(ui->tbvFunctions->selectionModel(), &QItemSelectionModel::currentChanged, this, &FunctionGraphDialog::showGraph);
}

FunctionGraphDialog::~FunctionGraphDialog() { delete ui; }

void FunctionGraphDialog::showGraph(const QModelIndex& current, const QModelIndex&)
{
    address_t address = r_doc->functionAt(current.row());
    m_functiongraphmodel->setGraph(r_doc->graph(address));
}
