#include "entrypointsdialog.h"
#include "ui_entrypointsdialog.h"

EntryPointsDialog::EntryPointsDialog(REDasm::DisassemblerAPI *disassembler, QWidget *parent) : QDialog(parent), ui(new Ui::EntryPointsDialog)
{
    ui->setupUi(this);

    m_entrypointsmodel = ListingFilterModel::createFilter<SymbolTableModel>(REDasm::ListingItem::AllItems, ui->tvEntryPoints);
    static_cast<SymbolTableModel*>(m_entrypointsmodel->sourceModel())->setSymbolFlags(REDasm::SymbolTypes::EntryPointMask);
    m_entrypointsmodel->setDisassembler(disassembler);

    ui->tvEntryPoints->setModel(m_entrypointsmodel);
    ui->tvEntryPoints->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    ui->tvEntryPoints->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
    ui->tvEntryPoints->horizontalHeader()->setSectionResizeMode(3, QHeaderView::ResizeToContents);
    ui->tvEntryPoints->horizontalHeader()->hideSection(2);
    ui->tvEntryPoints->verticalHeader()->setDefaultSectionSize(ui->tvEntryPoints->fontMetrics().lineSpacing());

    connect(ui->leFilter, &QLineEdit::textChanged, m_entrypointsmodel, &ListingFilterModel::setFilter);
    connect(ui->tvEntryPoints, &QTableView::doubleClicked, this, &EntryPointsDialog::symbolSelected);
    connect(ui->tvEntryPoints, &QTableView::doubleClicked, this, &EntryPointsDialog::accept);
}

EntryPointsDialog::~EntryPointsDialog() { delete ui; }
