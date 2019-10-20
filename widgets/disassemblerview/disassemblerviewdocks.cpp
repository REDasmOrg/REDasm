#include "disassemblerviewdocks.h"
#include <QHeaderView>
#include <QApplication>
#include <redasm/context.h>

DisassemblerViewDocks::DisassemblerViewDocks(QObject *parent) : QObject(parent), m_disassembler(nullptr)
{
    m_dockfunctions = this->findDock("dockFunctions");
    m_dockcalltree = this->findDock("dockCallTree");
    m_dockreferences = this->findDock("dockReferences");
    m_docklistingmap = this->findDock("dockListingMap");

    this->createFunctionsModel();
    this->createCallTreeModel();
    this->createReferencesModel();
    this->createListingMap();
}

void DisassemblerViewDocks::setDisassembler(const REDasm::DisassemblerPtr& disassembler)
{
    m_disassembler = disassembler;

    m_disassembler->busyChanged.connect(this, [&](REDasm::EventArgs*) {
        if(m_disassembler->busy())
            return;

        m_functionsview->resizeColumnToContents(0);
    });

    if(m_functionsmodel) m_functionsmodel->setDisassembler(disassembler);
    if(m_calltreemodel) m_calltreemodel->setDisassembler(disassembler);
    if(m_referencesmodel) m_referencesmodel->setDisassembler(disassembler);
    if(m_listingmap) m_listingmap->setDisassembler(disassembler);
}

ListingFilterModel *DisassemblerViewDocks::functionsModel() const { return m_functionsmodel; }
ReferencesModel *DisassemblerViewDocks::referencesModel() const { return m_referencesmodel; }
CallTreeModel *DisassemblerViewDocks::callTreeModel() { return m_calltreemodel; }
QTableView *DisassemblerViewDocks::functionsView() const { return m_functionsview; }
QTreeView *DisassemblerViewDocks::referencesView() const { return m_referencesview; }
QTreeView *DisassemblerViewDocks::callgraphView() const { return m_calltreeview; }

void DisassemblerViewDocks::initializeCallGraph(address_t address)
{
    if(m_disassembler->busy())
        return;

    m_dockcalltree->show();
    m_calltreemodel->initializeGraph(address);
    m_calltreeview->expandToDepth(0);
}

void DisassemblerViewDocks::updateCallGraph()
{
    REDasm::ListingDocument& document = m_disassembler->document();

    if(r_disasm->busy() || m_calltreeview->visibleRegion().isEmpty() || !r_docnew->currentItem().isValid())
        return;

    // const REDasm::ListingItem* item = document->functionStart(document->currentItem()->address_new);

    // if(!item)
    // {
    //     m_calltreemodel->clearGraph();
    //     return;
    // }

    // m_calltreemodel->initializeGraph(item->address_new);
    // m_calltreeview->expandToDepth(0);
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

void DisassemblerViewDocks::createCallTreeModel()
{
    m_calltreemodel = new CallTreeModel(this);

    m_calltreeview = m_dockcalltree->widget()->findChild<QTreeView*>("tvCallTree");
    m_calltreeview->setModel(m_calltreemodel);

    m_calltreeview->header()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    m_calltreeview->header()->setSectionResizeMode(1, QHeaderView::Stretch);
    m_calltreeview->header()->setSectionResizeMode(2, QHeaderView::ResizeToContents);

    connect(m_calltreeview, &QTreeView::expanded, m_calltreemodel, &CallTreeModel::populateCallGraph);
    connect(m_dockcalltree, &QDockWidget::visibilityChanged, this, &DisassemblerViewDocks::updateCallGraph);
}

void DisassemblerViewDocks::createFunctionsModel()
{
    m_functionsmodel = ListingFilterModel::createFilter<ListingItemModel>(REDasm::ListingItemType::FunctionItem, this);
    m_functionsview = m_dockfunctions->widget()->findChild<QTableView*>("tvFunctions");
    m_functionsview->setModel(m_functionsmodel);

    m_functionsview->verticalHeader()->setDefaultSectionSize(m_functionsview->verticalHeader()->minimumSectionSize());
    m_functionsview->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    m_functionsview->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
    m_functionsview->setColumnHidden(2, true);
    m_functionsview->setColumnHidden(3, true);
    m_functionsview->horizontalHeader()->moveSection(2, 1);
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

    m_listingmap = static_cast<ListingMap*>(m_docklistingmap->widget());
}
