#include "disassemblerviewdocks.h"
#include <QHeaderView>
#include <QApplication>

DisassemblerViewDocks::DisassemblerViewDocks(QObject *parent) : QObject(parent), m_disassembler(nullptr)
{
    m_docksymbols = this->findDock("dockSymbols");
    m_dockreferences = this->findDock("dockReferences");
    m_docklistingmap = this->findDock("dockListingMap");

    this->createSymbolsModel();
    this->createReferencesModel();
    this->createListingMap();
}

DisassemblerViewDocks::~DisassemblerViewDocks()
{
    if(m_listingmap)
        m_listingmap->deleteLater();
}

void DisassemblerViewDocks::setDisassembler(const REDasm::DisassemblerPtr& disassembler)
{
    m_disassembler = disassembler;

    EVENT_CONNECT(m_disassembler, busyChanged, this, [&]() {
        if(m_disassembler->busy())
            return;

        m_functionsview->resizeColumnToContents(0);
    });

    if(m_functionsmodel)
        m_functionsmodel->setDisassembler(disassembler);

    if(m_callgraphmodel)
        m_callgraphmodel->setDisassembler(disassembler);

    if(m_referencesmodel)
        m_referencesmodel->setDisassembler(disassembler);

    if(m_listingmap)
        m_listingmap->setDisassembler(disassembler);
}

ListingFilterModel *DisassemblerViewDocks::functionsModel() const { return m_functionsmodel; }
ReferencesModel *DisassemblerViewDocks::referencesModel() const { return m_referencesmodel; }
CallGraphModel *DisassemblerViewDocks::callGraphModel() { return m_callgraphmodel; }
QTableView *DisassemblerViewDocks::functionsView() const { return m_functionsview; }
QTreeView *DisassemblerViewDocks::referencesView() const { return m_referencesview; }
QTreeView *DisassemblerViewDocks::callgraphView() const { return m_callgraphview; }

void DisassemblerViewDocks::initializeCallGraph(address_t address)
{
    if(m_disassembler->busy())
        return;

    m_tabsmodel->setCurrentWidget(m_callgraphview->parentWidget());
    m_callgraphmodel->initializeGraph(address);
    m_callgraphview->expandToDepth(0);
}

void DisassemblerViewDocks::updateCallGraph()
{
    if(m_disassembler->busy() || (m_tabsmodel->currentIndex() != 1))
        return;

    REDasm::ListingDocument& document = m_disassembler->document();
    const REDasm::ListingItem* item = document->functionStart(document->currentItem()->address);

    if(!item)
    {
        m_callgraphmodel->clearGraph();
        return;
    }

    m_callgraphmodel->initializeGraph(item->address);
    m_callgraphview->expandToDepth(0);
}

QDockWidget *DisassemblerViewDocks::findDock(const QString &objectname) const
{
    QDockWidget* result = nullptr;

    for(const auto* widget : qApp->topLevelWidgets())
    {
        result = widget->findChild<QDockWidget*>(objectname);

        if(result)
            break;
    }

    return result;
}

void DisassemblerViewDocks::createCallGraphModel()
{
    m_callgraphmodel = new CallGraphModel(this);

    m_callgraphview = m_docksymbols->widget()->findChild<QTreeView*>("tvCallGraph");
    m_callgraphview->setModel(m_callgraphmodel);

    m_callgraphview->header()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    m_callgraphview->header()->setSectionResizeMode(1, QHeaderView::Stretch);
    m_callgraphview->header()->setSectionResizeMode(2, QHeaderView::ResizeToContents);

    connect(m_callgraphview, &QTreeView::expanded, m_callgraphmodel, &CallGraphModel::populateCallGraph);
}

void DisassemblerViewDocks::createFunctionsModel()
{
    m_functionsmodel = ListingFilterModel::createFilter<ListingItemModel>(REDasm::ListingItem::FunctionItem, this);
    m_functionsview = m_docksymbols->widget()->findChild<QTableView*>("tvFunctions");
    m_functionsview->setModel(m_functionsmodel);

    m_functionsview->verticalHeader()->setDefaultSectionSize(m_functionsview->verticalHeader()->minimumSectionSize());
    m_functionsview->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    m_functionsview->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
    m_functionsview->setColumnHidden(2, true);
    m_functionsview->setColumnHidden(3, true);
    m_functionsview->horizontalHeader()->moveSection(2, 1);
}

void DisassemblerViewDocks::createSymbolsModel()
{
    if(!m_docksymbols)
    {
        m_functionsmodel = nullptr;
        m_callgraphmodel = nullptr;
        return;
    }

    m_tabsmodel = m_docksymbols->widget()->findChild<QTabWidget*>("tabModels");
    connect(m_tabsmodel, &QTabWidget::currentChanged, this, &DisassemblerViewDocks::updateCallGraph);

    this->createFunctionsModel();
    this->createCallGraphModel();
}

void DisassemblerViewDocks::createReferencesModel()
{
    if(!m_dockreferences)
    {
        m_referencesmodel = nullptr;
        return;
    }

    m_referencesmodel = new ReferencesModel(this);
    m_referencesview = m_dockreferences->widget()->findChild<QTreeView*>("tvReferences");
    m_referencesview->setModel(m_referencesmodel);
    m_referencesview->setColumnHidden(0, true);
    m_referencesview->header()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    m_referencesview->header()->setSectionResizeMode(2, QHeaderView::Stretch);
}

void DisassemblerViewDocks::createListingMap()
{
    if(!m_docklistingmap)
    {
        m_listingmap = nullptr;
        return;
    }

    m_listingmap = new ListingMap();
    m_docklistingmap->setWidget(m_listingmap);
}
