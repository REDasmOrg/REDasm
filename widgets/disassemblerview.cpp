#include "disassemblerview.h"
#include "../hooks/disassemblerhooks.h"
#include "../models/symboltablemodel.h"
#include "../models/segmentsmodel.h"
#include "tabs/tabletab/tabletab.h"
#include "listing/listingsplitview.h"
#include "docks/listingmapdock/listingmapdock.h"
#include <QMessageBox>
#include <QBoxLayout>

DisassemblerView::DisassemblerView(QWidget *parent) : QWidget(parent) { }

DisassemblerView::~DisassemblerView()
{
    RDObject_Unsubscribe(m_context.get(), this);

    if(m_worker.valid()) m_worker.get();
    while(!m_docks.empty()) this->undock(*m_docks.begin());

    RD_Status("");
}

QWidget* DisassemblerView::currentWidget() const { return m_disassemblertabs->currentWidget(); }

ITableTab* DisassemblerView::showSegments(Qt::DockWidgetArea area)
{
    if(auto* t = this->findModelInTabs<SegmentsModel>())
    {
        m_disassemblertabs->setCurrentWidget(dynamic_cast<QWidget*>(t));
        return t;
    }

    TableTab* tabletab = this->createTable(new SegmentsModel(), "Segments");
    connect(tabletab, &TableTab::resizeColumns, tabletab, &TableTab::resizeAllColumns);

    if(area == Qt::NoDockWidgetArea) this->tab(tabletab);
    else this->dock(tabletab, area);
    return tabletab;
}

ITableTab* DisassemblerView::showFunctions(Qt::DockWidgetArea area)
{
    if(auto* t = this->findModelInTabs<ListingItemModel>())
    {
        if(t->model()->itemType() == DocumentItemType_Function)
        {
            m_disassemblertabs->setCurrentWidget(dynamic_cast<QWidget*>(t));
            return t;
        }
    }

    TableTab* tabletab = this->createTable(new ListingItemModel(DocumentItemType_Function), "Functions");
    tabletab->setColumnHidden(1);
    tabletab->setColumnHidden(2);
    connect(tabletab, &TableTab::resizeColumns, this, [tabletab]() { tabletab->resizeColumn(0); });

    if(area == Qt::NoDockWidgetArea) this->tab(tabletab);
    else this->dock(tabletab, area);
    return tabletab;
}

ITableTab* DisassemblerView::showExports(Qt::DockWidgetArea area)
{
    if(auto* t = this->findSymbolModelInTabs(SymbolType_None, SymbolFlags_Export))
    {
        m_disassemblertabs->setCurrentWidget(dynamic_cast<QWidget*>(t));
        return t;
    }

    auto* model = new SymbolTableModel(DocumentItemType_All);
    model->setSymbolFlags(SymbolFlags_Export);

    TableTab* tabletab = this->createTable(model, "Exports");
    connect(tabletab, &TableTab::resizeColumns, tabletab, &TableTab::resizeAllColumns);

    if(area == Qt::NoDockWidgetArea) this->tab(tabletab);
    else this->dock(tabletab, area);
    return tabletab;
}

ITableTab* DisassemblerView::showImports(Qt::DockWidgetArea area)
{
    if(auto* t = this->findSymbolModelInTabs(SymbolType_Import, SymbolFlags_None))
    {
        m_disassemblertabs->setCurrentWidget(dynamic_cast<QWidget*>(t));
        return t;
    }

    auto* model = new SymbolTableModel(DocumentItemType_Symbol);
    model->setSymbolType(SymbolType_Import);

    TableTab* tabletab = this->createTable(model, "Imports");
    connect(tabletab, &TableTab::resizeColumns, tabletab, &TableTab::resizeAllColumns);

    if(area == Qt::NoDockWidgetArea) this->tab(tabletab);
    else this->dock(tabletab, area);
    return tabletab;
}

ITableTab* DisassemblerView::showStrings(Qt::DockWidgetArea area)
{
    if(auto* t = this->findSymbolModelInTabs(SymbolType_String, SymbolFlags_None))
    {
        m_disassemblertabs->setCurrentWidget(dynamic_cast<QWidget*>(t));
        return t;
    }

    auto* model = new SymbolTableModel(DocumentItemType_Symbol);
    model->setSymbolType(SymbolType_String);

    TableTab* tabletab = this->createTable(model, "Strings");
    connect(tabletab, &TableTab::resizeColumns, tabletab, &TableTab::resizeAllColumns);

    if(area == Qt::NoDockWidgetArea) this->tab(tabletab);
    else this->dock(tabletab, area);
    return tabletab;
}

const RDContextPtr& DisassemblerView::context() const { return m_context; }

ITableTab* DisassemblerView::findSymbolModelInTabs(rd_type type, rd_flag flags) const
{
    for(int i = 0; i < m_disassemblertabs->count(); i++)
    {
        auto* tabletab = dynamic_cast<ITableTab*>(m_disassemblertabs->widget(i));
        if(!tabletab) continue;

        auto* symboltablemodel = dynamic_cast<SymbolTableModel*>(tabletab->model());
        if(!symboltablemodel || (symboltablemodel->symbolType() != type)) continue;
        if(symboltablemodel->symbolFlags() != flags) continue;
        return tabletab;
    }

    return nullptr;
}

TableTab* DisassemblerView::createTable(ListingItemModel* model, const QString& title)
{
    TableTab* tabletab = new TableTab(model);
    model->setParent(tabletab);
    tabletab->setWindowTitle(title);
    return tabletab;
}

void DisassemblerView::listenEvents(const RDEventArgs* e)
{
    auto* thethis = reinterpret_cast<DisassemblerView*>(e->userdata);

    switch(e->id)
    {
        case Event_BusyChanged:
            QMetaObject::invokeMethod(DisassemblerHooks::instance(), "updateViewWidgets", Qt::QueuedConnection, Q_ARG(bool, RDContext_IsBusy(thethis->m_context.get())));
            break;

        case Event_Error: {
            const auto* ee = reinterpret_cast<const RDErrorEventArgs*>(e);
            QMetaObject::invokeMethod(DisassemblerHooks::instance(), "showMessage", Qt::QueuedConnection,
                                      Q_ARG(QString, "Error"),
                                      Q_ARG(QString, ee->message),
                                      Q_ARG(size_t, QMessageBox::Critical));
            break;
        }
    }
}

SurfaceQt* DisassemblerView::showListing()
{
    auto* listingsplitview = new ListingSplitView(m_context);
    m_disassemblertabs->insertTab(0, listingsplitview, listingsplitview->windowTitle());
    //return listingcontainer->surface();
    return nullptr;
}

bool DisassemblerView::focusOn(QWidget* w)
{
    QWidget* tw = nullptr;

    for(int i = 0; i < m_disassemblertabs->count(); i++)
    {
        if(m_disassemblertabs->widget(i) != w) continue;
        tw = w;
        break;
    }

    if(!tw) return false;
    m_disassemblertabs->setCurrentWidget(tw);
    return true;
}

void DisassemblerView::setContext(const RDContextPtr& ctx)
{
    m_context = ctx;
    m_disassemblertabs = new DisassemblerTabs(ctx, this);

    QBoxLayout* boxlayout = new QBoxLayout(QBoxLayout::TopToBottom);
    boxlayout->setContentsMargins(0, 0, 0, 0);
    boxlayout->setSpacing(0);
    boxlayout->addWidget(m_disassemblertabs);
    this->setLayout(boxlayout);

    this->showListing();
    m_listingmapdock = new ListingMapDock(ctx);

    this->showFunctions(Qt::LeftDockWidgetArea);
    this->showSegments();
    this->showExports();
    this->showImports();
    this->showStrings();
    this->dock(m_listingmapdock, Qt::RightDockWidgetArea);

    RDObject_Subscribe(ctx.get(), this, &DisassemblerView::listenEvents, this);

    m_worker = std::async([&, ctx]() { // Capture 'disassembler' by value
        RDContext_Disassemble(ctx.get());
        QMetaObject::invokeMethod(DisassemblerHooks::instance(), "enableViewCommands", Qt::QueuedConnection, Q_ARG(bool, true));
    });
}

void DisassemblerView::tab(QWidget* w, int index)
{
    if(index != -1) m_disassemblertabs->insertTab(index, w, w->windowTitle());
    else m_disassemblertabs->addTab(w, w->windowTitle());
}

void DisassemblerView::tabify(QDockWidget* first, QDockWidget* second)
{
    DisassemblerHooks::instance()->mainWindow()->tabifyDockWidget(first, second);
}

void DisassemblerView::dock(QWidget* w, Qt::DockWidgetArea area)
{
    QDockWidget* dw = dynamic_cast<QDockWidget*>(w);

    if(!dw)
    {
        dw = new QDockWidget(this);
        w->setParent(dw); // Take ownership
        dw->setWindowTitle(w->windowTitle());
        dw->setWidget(w);
    }

    m_docks.insert(dw);
    DisassemblerHooks::instance()->mainWindow()->addDockWidget(area, dw); // Takes Ownership
}

void DisassemblerView::undock(QDockWidget* dw)
{
    m_docks.remove(dw);
    DisassemblerHooks::instance()->mainWindow()->removeDockWidget(dw);
    dw->deleteLater();
}
