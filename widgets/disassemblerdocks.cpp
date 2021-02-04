#include "disassemblerdocks.h"
#include "../hooks/disassemblerhooks.h"
#include "../models/symboltablemodel.h"
#include "../models/segmentsmodel.h"
#include "widgets/outputwidget.h"
#include "tabs/tabletab/tabletab.h"
#include "listing/listingsplitview.h"
#include "listing/listingview.h"
#include "listingmap/listingmap.h"
#include <QMessageBox>

DisassemblerDocks::DisassemblerDocks(QObject* parent) : QObject(parent) { }

DisassemblerDocks::~DisassemblerDocks()
{
    RDObject_Unsubscribe(m_context.get(), this);
    if(m_worker.valid()) m_worker.get();
    RD_Status("");
}

void DisassemblerDocks::showSegments()
{
    TableTab* tabletab = this->createTable(new SegmentsModel(), "Segments");
    tabletab->moveSection(7, 0);
    connect(tabletab, &TableTab::resizeColumns, tabletab, &TableTab::resizeAllColumns);
    DisassemblerHooks::tabify(tabletab, "segments");
}

void DisassemblerDocks::showFunctions()
{
    TableTab* tabletab = this->createTable(new ListingItemModel(DocumentItemType_Function), "Functions");
    tabletab->setColumnHidden(1);
    tabletab->setColumnHidden(2);
    connect(tabletab, &TableTab::resizeColumns, this, [tabletab]() { tabletab->resizeColumn(0); });

    auto* dock = DisassemblerHooks::dockify(tabletab, "functions");
    DisassemblerHooks::mainWindow()->addDockWidget(dock, KDDockWidgets::Location_OnLeft, nullptr, tabletab->sizeHint());
}

void DisassemblerDocks::showExports()
{
    auto* model = new SymbolTableModel(DocumentItemType_All);
    model->setSymbolFlags(SymbolFlags_Export);

    TableTab* tabletab = this->createTable(model, "Exports");
    connect(tabletab, &TableTab::resizeColumns, tabletab, &TableTab::resizeAllColumns);
    DisassemblerHooks::tabify(tabletab, "exports");
}

void DisassemblerDocks::showImports()
{
    auto* model = new SymbolTableModel(DocumentItemType_Symbol);
    model->setSymbolType(SymbolType_Import);

    TableTab* tabletab = this->createTable(model, "Imports");
    connect(tabletab, &TableTab::resizeColumns, tabletab, &TableTab::resizeAllColumns);
    DisassemblerHooks::tabify(tabletab, "imports");
}

void DisassemblerDocks::showStrings()
{
    auto* model = new SymbolTableModel(DocumentItemType_Symbol);
    model->setSymbolType(SymbolType_String);

    TableTab* tabletab = this->createTable(model, "Strings");
    connect(tabletab, &TableTab::resizeColumns, tabletab, &TableTab::resizeAllColumns);
    DisassemblerHooks::tabify(tabletab, "strings");
}

const RDContextPtr& DisassemblerDocks::context() const { return m_context; }

TableTab* DisassemblerDocks::createTable(ListingItemModel* model, const QString& title)
{
    TableTab* tabletab = new TableTab(model);
    model->setParent(tabletab);
    tabletab->setWindowTitle(title);
    return tabletab;
}

void DisassemblerDocks::listenEvents(const RDEventArgs* e)
{
    auto* thethis = reinterpret_cast<DisassemblerDocks*>(e->userdata);

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

KDDockWidgets::DockWidget* DisassemblerDocks::showListing() { return DisassemblerHooks::tabify(new ListingSplitView(m_context)); }

void DisassemblerDocks::setContext(const RDContextPtr& ctx)
{
    m_context = ctx;
    m_listingdock = this->showListing();

    this->showSegments();
    this->showExports();
    this->showImports();
    this->showStrings();

    this->showFunctions();
    m_listingmap = new ListingMap(ctx);

    auto* mapdock = DisassemblerHooks::dockify(m_listingmap, "map");
    DisassemblerHooks::mainWindow()->addDockWidget(mapdock, KDDockWidgets::Location_OnRight, m_listingdock, m_listingmap->sizeHint());
    m_listingdock->setAsCurrentTab();

    RDObject_Subscribe(ctx.get(), this, &DisassemblerDocks::listenEvents, this);

    m_worker = std::async([&, ctx]() { // Capture 'disassembler' by value
        RDContext_Disassemble(ctx.get());
        QMetaObject::invokeMethod(DisassemblerHooks::instance(), "enableViewCommands", Qt::QueuedConnection, Q_ARG(bool, true));
    });
}
