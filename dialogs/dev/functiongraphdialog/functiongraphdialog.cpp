#include "functiongraphdialog.h"
#include "ui_functiongraphdialog.h"
#include <QClipboard>

FunctionGraphDialog::FunctionGraphDialog(QWidget *parent) : QDialog(parent), ui(new Ui::FunctionGraphDialog)
{
    ui->setupUi(this);
    ui->splitter->setStretchFactor(1, 1);
}

FunctionGraphDialog::~FunctionGraphDialog() { delete ui; }

void FunctionGraphDialog::setDisassembler(RDDisassembler* disassembler)
{
    if(ui->tbvFunctions->selectionMode())
        disconnect(ui->tbvFunctions->selectionModel(), &QItemSelectionModel::currentChanged, this, nullptr);

    m_functionlistmodel = new FunctionListModel(ui->tbvFunctions);
    m_functionlistmodel->setDisassembler(disassembler);

    m_functiongraphmodel = new FunctionGraphModel(disassembler, ui->tbvGraph);
    m_sortedblocksmodel = new QSortFilterProxyModel(ui->tbvGraph);
    m_sortedblocksmodel->setSourceModel(m_functiongraphmodel);
    m_sortedblocksmodel->setSortRole(Qt::UserRole);

    ui->tbvFunctions->setModel(m_functionlistmodel);
    ui->tbvGraph->setModel(m_sortedblocksmodel);

    ui->tbvFunctions->verticalHeader()->setDefaultSectionSize(ui->tbvFunctions->verticalHeader()->minimumSectionSize());
    ui->tbvFunctions->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    ui->tbvFunctions->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
    ui->tbvFunctions->horizontalHeader()->hideSection(2);
    ui->tbvFunctions->horizontalHeader()->hideSection(3);

    ui->tbvGraph->verticalHeader()->setDefaultSectionSize(ui->tbvFunctions->verticalHeader()->minimumSectionSize());
    ui->tbvGraph->horizontalHeader()->setSectionResizeMode(QHeaderView::ResizeToContents);

    connect(ui->tbvFunctions->selectionModel(), &QItemSelectionModel::currentChanged, this, &FunctionGraphDialog::showGraph);
    connect(ui->pbCopy, &QPushButton::clicked, this, &FunctionGraphDialog::copyGraph);
}

void FunctionGraphDialog::showGraph(const QModelIndex& current, const QModelIndex&)
{
    const RDGraph* graph = m_functionlistmodel->graph(current);
    m_functiongraphmodel->setGraph(graph);
    m_sortedblocksmodel->sort(0);
}

void FunctionGraphDialog::copyGraph() const
{
    QModelIndex index = ui->tbvFunctions->currentIndex();
    if(!index.isValid()) return;

    const RDGraph* graph = m_functionlistmodel->graph(index);
    if(!graph) return;

    QString g = "digraph G {\n";

    const RDGraphNode* nodes = nullptr;
    size_t nc = RDGraph_GetNodes(graph, &nodes);

    for(size_t i = 0; i < nc; i++)
    {
        const RDGraphEdge* edges = nullptr;
        size_t oc = RDGraph_GetOutgoing(graph, nodes[i], &edges);

        const RDFunctionBasicBlock *srcfbb = nullptr, *tgtfbb = nullptr;
        RDFunctionGraph_GetBasicBlock(graph, nodes[i], &srcfbb);

        for(size_t j = 0; j < oc; j++)
        {
            RDFunctionGraph_GetBasicBlock(graph, edges[j].target, &tgtfbb);
            QString srcaddress = RD_ToHex(RDFunctionBasicBlock_GetStartAddress(srcfbb));
            QString tgtaddress = RD_ToHex(RDFunctionBasicBlock_GetStartAddress(tgtfbb));
            g += QString("\t\"%1\" -> \"%2\";\n").arg(srcaddress, tgtaddress);
        }
    }

    g += "}";
    qApp->clipboard()->setText(g);
}
