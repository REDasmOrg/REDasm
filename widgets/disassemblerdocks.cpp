#include "disassemblerdocks.h"
#include "../hooks/disassemblerhooks.h"
#include "../models/symboltablemodel.h"
#include "../models/segmentsmodel.h"
#include "widgets/dashboard/analysiswidget.h"
#include "widgets/outputwidget.h"
#include "listing/listingsplitview.h"
#include "listing/listingview.h"
#include "listingmap/listingmap.h"
#include "tablewidget.h"
#include <QMessageBox>

DisassemblerDocks::DisassemblerDocks(QObject* parent) : QObject(parent) { }

DisassemblerDocks::~DisassemblerDocks()
{
    RDObject_Unsubscribe(m_context.get(), this);
    if(m_worker.valid()) m_worker.get();
    RD_Status("");
}

void DisassemblerDocks::showSegments() const
{
    TableWidget* tw = this->createTable(new SegmentsModel(), "Segments");
    tw->moveSection(7, 0);
    connect(tw, &TableWidget::resizeColumns, tw, &TableWidget::resizeAllColumns);
    DisassemblerHooks::tabify(tw);
}

void DisassemblerDocks::showFunctions() const
{
    TableWidget* tw = this->createTable(new ListingItemModel(DocumentItemType_Function), "Functions");
    tw->setColumnHidden(1);
    tw->setColumnHidden(2);
    connect(tw, &TableWidget::resizeColumns, this, [tw]() { tw->resizeColumn(0); });

    auto* dock = DisassemblerHooks::dockify(tw);
    DisassemblerHooks::mainWindow()->addDockWidget(dock, KDDockWidgets::Location_OnLeft, nullptr, tw->sizeHint());
}

void DisassemblerDocks::showExports() const
{
    auto* model = new SymbolTableModel(DocumentItemType_All);
    model->setSymbolFlags(SymbolFlags_Export);

    TableWidget* tw = this->createTable(model, "Exports");
    connect(tw, &TableWidget::resizeColumns, tw, &TableWidget::resizeAllColumns);
    DisassemblerHooks::tabify(tw);
}

void DisassemblerDocks::showImports() const
{
    auto* model = new SymbolTableModel(DocumentItemType_Symbol);
    model->setSymbolType(SymbolType_Import);

    TableWidget* tw = this->createTable(model, "Imports");
    connect(tw, &TableWidget::resizeColumns, tw, &TableWidget::resizeAllColumns);
    DisassemblerHooks::tabify(tw);
}

void DisassemblerDocks::showStrings() const
{
    auto* model = new SymbolTableModel(DocumentItemType_Symbol);
    model->setSymbolType(SymbolType_String);

    TableWidget* tw = this->createTable(model, "Strings");
    connect(tw, &TableWidget::resizeColumns, tw, &TableWidget::resizeAllColumns);
    DisassemblerHooks::tabify(tw);
}

void DisassemblerDocks::showMap(KDDockWidgets::DockWidget* relative) const
{
    auto* listingmap = new ListingMap(m_context);
    auto* mapdock = DisassemblerHooks::dockify(listingmap);

    KDDockWidgets::InitialOption opt(listingmap->sizeHint());
    opt.preferredLength(Qt::Vertical);
    DisassemblerHooks::mainWindow()->addDockWidget(mapdock, KDDockWidgets::Location_OnRight, relative, opt);
}

void DisassemblerDocks::onItemDoubleClicked(const QModelIndex& index)
{
    auto* surface = DisassemblerHooks::activeSurface();
    if(!surface) return;

    auto* listingitemmodel = dynamic_cast<const ListingItemModel*>(index.model());
    if(!listingitemmodel) return;

    const RDDocumentItem& item = listingitemmodel->item(index);
    surface->goTo(&item);
    DisassemblerHooks::focusOn(surface->widget());
}

void DisassemblerDocks::showDisassembly()
{
    auto* listingdock = this->showListing();
    this->showSegments();
    this->showExports();
    this->showImports();
    this->showStrings();
    this->showFunctions();
    this->showMap(listingdock);
    listingdock->setAsCurrentTab();

    DisassemblerHooks::instance()->setTabBarVisible(true);
    DisassemblerHooks::instance()->enableViewCommands(true);
}

const RDContextPtr& DisassemblerDocks::context() const { return m_context; }

TableWidget* DisassemblerDocks::createTable(ListingItemModel* model, const QString& title) const
{
    model->setContext(m_context);

    TableWidget* tw = new TableWidget();
    tw->setToggleFilter(true);
    tw->setWindowTitle(title);
    tw->setModel(model);

    connect(tw, &TableWidget::doubleClicked, this, &DisassemblerDocks::onItemDoubleClicked);
    return tw;
}

void DisassemblerDocks::listenEvents(const RDEventArgs* e)
{
    auto* thethis = reinterpret_cast<DisassemblerDocks*>(e->owner);

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

DockWidget* DisassemblerDocks::showListing() const { return DisassemblerHooks::tabify(new ListingSplitView(m_context)); }

void DisassemblerDocks::setContext(const RDContextPtr& ctx)
{
    m_context = ctx;
    auto* analysiswidget = new AnalysisWidget(ctx);
    m_analysisdock = DisassemblerHooks::dockify(analysiswidget, KDDockWidgets::DockWidget::Option_NotClosable);

    connect(analysiswidget, &AnalysisWidget::listingClicked, this, [=]() {
        m_analysisdock->hide();
        m_analysisdock->deleteLater();
        this->showDisassembly();
    });

    DisassemblerHooks::mainWindow()->addDockWidgetAsTab(m_analysisdock);

    RDObject_Subscribe(ctx.get(), this, &DisassemblerDocks::listenEvents, nullptr);
    m_worker = std::async([&, ctx]() {  RDContext_Disassemble(ctx.get()); });
}
