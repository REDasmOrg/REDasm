#include "listingview.h"
#include "../../dialogs/referencesdialog/referencesdialog.h"
#include "../../dialogs/gotodialog/gotodialog.h"
#include "../../hooks/disassemblerhooks.h"
#include "../../redasmsettings.h"
#include <qhexview/document/buffer/qmemoryrefbuffer.h>
#include <qhexview/document/qhexdocument.h>
#include <unordered_map>
#include <unordered_set>
#include <QInputDialog>
#include <QMessageBox>
#include <QMenu>

ListingView::ListingView(const RDContextPtr& ctx, QWidget *parent) : QStackedWidget(parent), m_context(ctx)
{
    this->setWindowTitle("Listing");

    m_textview = new ListingTextView(ctx);
    m_graphview = new ListingGraphView(ctx);

    m_hexview = new QHexView(this);
    m_hexview->setFont(REDasmSettings::font());
    m_hexview->setReadOnly(true);
    this->prepareHexDocument();

    this->addWidget(m_textview);
    this->addWidget(m_graphview);
    this->addWidget(m_hexview);

    m_hexview->installEventFilter(this);
    m_graphview->installEventFilter(this);
    m_textview->textWidget()->installEventFilter(this);
    m_textview->textWidget()->setFocus();

    std::unordered_map<QWidget*, QMenu*> menu = {
        { m_textview->textWidget(), this->createActions(m_textview->textWidget()) },
        { m_graphview, this->createActions(m_graphview) },
    };

    for(const auto& item : menu)
    {
        connect(item.first, &ListingTextWidget::customContextMenuRequested, this, [=](const QPoint&) {
            item.second->popup(QCursor::pos());
        });
    }

    connect(m_textview->surface(), &SurfaceQt::historyChanged, this, &ListingView::historyChanged);
}

rd_address ListingView::currentAddress() const
{
    auto* isurface = this->currentISurface();
    return isurface ? isurface->currentAddress() : RD_NVAL;
}

void ListingView::switchToGraph()
{
    rd_address address = this->currentAddress();
    if((address == RD_NVAL) || !m_graphview->renderGraph(address)) return;

    this->setCurrentWidget(m_graphview);
    m_graphview->setFocus();

    if(m_graphview->surface()) // Connect to the new surface
        connect(m_graphview->surface(), &SurfaceQt::historyChanged, this, &ListingView::historyChanged);

    Q_EMIT historyChanged();
}

void ListingView::switchToListing()
{
    if(this->currentISurface())
    {
        rd_address address = this->currentAddress();
        if(address == RD_NVAL) return;

        this->setCurrentWidget(m_textview);
        m_textview->textWidget()->seek(address);
    }

    m_textview->textWidget()->setFocus();
    Q_EMIT historyChanged();
}

void ListingView::switchToHex()
{
    rd_address address = this->currentAddress();
    if(address == RD_NVAL) return;

    auto loc = RD_Offset(m_context.get(), address);
    if(!loc.valid) return;

    m_hexview->document()->cursor()->moveTo(loc.offset);
    this->setCurrentWidget(m_hexview);

    Q_EMIT historyChanged();
}

void ListingView::switchMode()
{
    if(m_graphview->isVisible()) this->switchToListing();
    else this->switchToGraph();
}

bool ListingView::eventFilter(QObject* object, QEvent* event)
{
    if(event->type() != QEvent::KeyPress) return false;

    QKeyEvent* keyevent = static_cast<QKeyEvent*>(event);
    if(keyevent->key() != Qt::Key_Space) return false;

    std::unordered_set<QObject*> widgets = { m_textview->textWidget(),
                                             m_graphview,
                                             m_hexview };

    if(!widgets.count(object)) return false;

    if(this->currentWidget() == m_hexview) this->switchToListing();
    else this->switchMode();
    return true;
}

void ListingView::adjustActions()
{
    QMenu* menu = static_cast<QMenu*>(this->sender());
    std::unordered_map<int, QAction*> actions;

    for(QAction* action : menu->actions())
    {
        QVariant data = action->data();
        if(!data.isNull()) actions[data.toInt()] = action;
    }

    ISurface* surface = dynamic_cast<ISurface*>(menu->parentWidget());

    rd_address address = this->currentAddress();
    if(address == RD_NVAL) return;

    RDDocument* doc = RDContext_GetDocument(surface->context().get());

    actions[ListingView::Action_Back]->setVisible(surface->canGoBack());
    actions[ListingView::Action_Forward]->setVisible(surface->canGoForward());
    actions[ListingView::Action_Copy]->setVisible(surface->hasSelection());
    actions[ListingView::Action_Goto]->setVisible(!RDContext_IsBusy(surface->context().get()));

    RDSegment itemsegment, symbolsegment;
    rd_address labeladdress;

    if(surface->currentLabel(&labeladdress).isEmpty())
    {
        bool hassymbolsegment = RDDocument_AddressToSegment(doc, address, &symbolsegment);
        RDLocation funcstart = RDContext_GetFunctionStart(surface->context().get(), address);
        const char* funcname = funcstart.valid ? RDDocument_GetLabel(doc, funcstart.value) : nullptr;

        actions[ListingView::Action_Rename]->setVisible(false);
        actions[ListingView::Action_XRefs]->setVisible(false);
        actions[ListingView::Action_Follow]->setVisible(false);
        actions[ListingView::Action_FollowPointerHexDump]->setVisible(false);

        if(!RDContext_IsBusy(surface->context().get()))
        {
            bool ok = false;
            RDSegment currentsegment;
            rd_address currentaddress = surface->currentWord().toUInt(&ok, 16);
            bool hascurrentsegment = ok ? RDDocument_AddressToSegment(doc, currentaddress, &currentsegment) : false;

            actions[ListingView::Action_CreateFunction]->setVisible(hascurrentsegment && HAS_FLAG(&currentsegment, SegmentFlags_Code));

            if(hascurrentsegment)
                actions[ListingView::Action_CreateFunction]->setText(QString("Create Function @ %1").arg(RD_ToHexAuto(surface->context().get(), currentaddress)));
        }
        else
            actions[ListingView::Action_CreateFunction]->setVisible(false);

        actions[ListingView::Action_CallGraph]->setVisible(hassymbolsegment && HAS_FLAG(&symbolsegment, SegmentFlags_Code));
        actions[ListingView::Action_HexDumpFunction]->setVisible(funcname);
        actions[ListingView::Action_HexDump]->setVisible(true);
        return;
    }

    rd_flag labelflags = RDDocument_GetFlags(doc, labeladdress);
    bool hasitemsegment = RDDocument_AddressToSegment(doc, address, &itemsegment);
    const char* labelname = RDDocument_GetLabel(doc, labeladdress);
    bool hassymbolsegment = RDDocument_AddressToSegment(doc, labeladdress, &symbolsegment);

    actions[ListingView::Action_CreateFunction]->setText(QString("Create Function @ %1").arg(RD_ToHexAuto(surface->context().get(), labeladdress)));

    actions[ListingView::Action_CreateFunction]->setVisible(!RDContext_IsBusy(surface->context().get()) &&
                                                            (hassymbolsegment && HAS_FLAG(&symbolsegment,SegmentFlags_Code)) &&
                                                            labelflags & AddressFlags_Function);


    actions[ListingView::Action_FollowPointerHexDump]->setText(QString("Follow %1 pointer in Hex Dump").arg(labelname));
    actions[ListingView::Action_FollowPointerHexDump]->setVisible(labelflags & AddressFlags_Pointer);

    actions[ListingView::Action_XRefs]->setText(QString("Cross Reference %1").arg(labelname));
    actions[ListingView::Action_XRefs]->setVisible(!RDContext_IsBusy(surface->context().get()));

    actions[ListingView::Action_Rename]->setText(QString("Rename %1").arg(labelname));
    actions[ListingView::Action_Rename]->setVisible(!RDContext_IsBusy(surface->context().get()));

    actions[ListingView::Action_CallGraph]->setText("Callgraph");
    actions[ListingView::Action_CallGraph]->setVisible(!RDContext_IsBusy(surface->context().get()) && (labelflags & AddressFlags_Function));

    actions[ListingView::Action_Follow]->setText(QString("Follow %1").arg(labelname));
    actions[ListingView::Action_Follow]->setVisible(labelflags & AddressFlags_Location);
    actions[ListingView::Action_Comment]->setVisible(!RDContext_IsBusy(surface->context().get()));

    actions[ListingView::Action_HexDump]->setVisible(hassymbolsegment && HAS_FLAG(&symbolsegment, SegmentFlags_Bss));
    actions[ListingView::Action_HexDumpFunction]->setVisible(hasitemsegment && !HAS_FLAG(&itemsegment, SegmentFlags_Bss) && HAS_FLAG(&itemsegment, SegmentFlags_Code));
}

ISurface* ListingView::currentISurface() const { return dynamic_cast<ISurface*>(this->currentWidget()); }

QMenu* ListingView::createActions(ISurface* surface)
{
    QMenu* contextmenu = new QMenu(surface->widget());
    std::unordered_map<int, QAction*> actions;

    actions[ListingView::Action_Rename] = contextmenu->addAction("Rename", this, [&, surface]() {
        rd_address address;
        if(surface->currentLabel(&address).isEmpty()) return;

        RDDocument* doc = RDContext_GetDocument(surface->context().get());
        const char* labelname = RDDocument_GetLabel(doc, address);
        if(!labelname) return;

        bool ok = false;
        QString res = QInputDialog::getText(surface->widget(),
                                            "Rename @ " + QString::fromStdString(rd_tohexauto(surface->context().get(), address)),
                                            "Symbol name:", QLineEdit::Normal, labelname, &ok);

        if(!ok) return;
        RDDocument_UpdateLabel(doc, address, qUtf8Printable(res));
    }, QKeySequence(Qt::Key_N));

    actions[ListingView::Action_Comment] = contextmenu->addAction("Comment", this, [&, surface]() {
        rd_address address = surface->currentAddress();
        if(address == RD_NVAL) return;

        RDDocument* doc = RDContext_GetDocument(surface->context().get());

        bool ok = false;
        QString res = QInputDialog::getMultiLineText(surface->widget(),
                                                     "Comment @ " + QString::fromStdString(rd_tohexauto(surface->context().get(), address)),
                                                     "Insert a comment (leave blank to remove):",
                                                     RDDocument_GetComments(doc, address), &ok);

        if(!ok) return;
        RDDocument_SetComments(doc, address, qUtf8Printable(res));
    }, QKeySequence(Qt::Key_Semicolon));

    contextmenu->addSeparator();

    actions[ListingView::Action_XRefs] = contextmenu->addAction("Cross References", this, [&, surface]() {
        rd_address address;
        if(surface->currentLabel(&address).size()) this->showReferences(address);
    }, QKeySequence(Qt::Key_X));

    actions[ListingView::Action_Follow] = contextmenu->addAction("Follow", this, [surface]() {
        rd_address address;
        if(surface->currentLabel(&address).size()) surface->goTo(address);
    });

    actions[ListingView::Action_FollowPointerHexDump] = contextmenu->addAction("Follow pointer in Hex Dump", this, [&, surface]() {
    });

    actions[ListingView::Action_Goto] = contextmenu->addAction("Goto...", this, [&]() { this->showGoto(); }, QKeySequence(Qt::Key_G));

    actions[ListingView::Action_CallGraph] = contextmenu->addAction("Call Graph", this, [&, surface]() {
        rd_address address = surface->currentAddress();
        if(address != RD_NVAL) DisassemblerHooks::instance()->showCallGraph(address);
    }, QKeySequence(Qt::CTRL + Qt::Key_G));

    contextmenu->addSeparator();

    actions[ListingView::Action_SwitchView] = contextmenu->addAction("Switch View", this, [&]() { this->switchMode(); });
    actions[ListingView::Action_HexDump] = contextmenu->addAction("Show Hex Dump", this, [&]() { this->switchToHex(); }, QKeySequence(Qt::CTRL + Qt::Key_X));

    actions[ListingView::Action_HexDumpFunction] = contextmenu->addAction("Hex Dump Function", this, [&, surface]() {
        rd_address address = surface->currentAddress();
        if(address == RD_NVAL) return;

        rd_address resaddress = RD_NVAL;
        const char* hexdump = RDContext_FunctionHexDump(surface->context().get(), address, &resaddress);
        if(!hexdump) return;

        RDDocument* doc = RDContext_GetDocument(surface->context().get());
        RD_Log(qUtf8Printable(QString("%1: %2").arg(RDDocument_GetLabel(doc, resaddress), hexdump)));
    });

    actions[ListingView::Action_CreateFunction] = contextmenu->addAction("Create Function", this, [&, surface]() {
        rd_address address;

        if(surface->currentLabel(&address).isEmpty()) {
            rd_log("Cannot create function @ " + rd_tohex(address));
            return;
        }

        m_worker = std::async([&]() {
            RDDocument* doc = RDContext_GetDocument(surface->context().get());
            RDDocument_CreateFunction(doc, address, nullptr);
        });
    }, QKeySequence(Qt::SHIFT + Qt::Key_C));

    contextmenu->addSeparator();
    actions[ListingView::Action_Back] = contextmenu->addAction("Back", this, [surface]() { surface->goBack(); }, QKeySequence(Qt::CTRL + Qt::Key_Left));
    actions[ListingView::Action_Forward] = contextmenu->addAction("Forward", this, [surface]() { surface->goForward(); }, QKeySequence(Qt::CTRL + Qt::Key_Right));
    contextmenu->addSeparator();
    actions[ListingView::Action_Copy] = contextmenu->addAction("Copy", this, [surface]() { surface->copy(); }, QKeySequence(QKeySequence::Copy));

    for(auto& [type, action] : actions)
    {
        action->setShortcutContext(Qt::ShortcutContext::WidgetWithChildrenShortcut);
        action->setData(type);
    }

    surface->widget()->addAction(actions[ListingView::Action_Rename]);
    surface->widget()->addAction(actions[ListingView::Action_XRefs]);
    surface->widget()->addAction(actions[ListingView::Action_Comment]);
    surface->widget()->addAction(actions[ListingView::Action_Goto]);
    surface->widget()->addAction(actions[ListingView::Action_CallGraph]);
    surface->widget()->addAction(actions[ListingView::Action_HexDump]);
    surface->widget()->addAction(actions[ListingView::Action_CreateFunction]);
    surface->widget()->addAction(actions[ListingView::Action_Back]);
    surface->widget()->addAction(actions[ListingView::Action_Forward]);
    surface->widget()->addAction(actions[ListingView::Action_Copy]);

    connect(contextmenu, &QMenu::aboutToShow, this, &ListingView::adjustActions);
    return contextmenu;
}

void ListingView::prepareHexDocument()
{
    auto* buffer = RDContext_GetBuffer(m_context.get());
    m_hexview->setDocument(QHexDocument::fromMemory<QMemoryRefBuffer>(reinterpret_cast<char*>(RDBuffer_Data(buffer)),
                                                                      static_cast<int>(RDBuffer_Size(buffer)), m_hexview));
}

void ListingView::showReferences(rd_address address)
{
    auto* isurface = this->currentISurface();
    if(!isurface) return;

    RDDocument* doc = RDContext_GetDocument(m_context.get());

    const char* label = RDDocument_GetLabel(doc, address);
    if(!label) return;

    const RDNet* net = RDContext_GetNet(m_context.get());

    if(!RDNet_GetReferences(net, address, nullptr))
    {
        QMessageBox::information(nullptr, "No References", QString("There are no references to %1 ").arg(label));
        return;
    }

    ReferencesDialog dlgreferences(m_context, isurface, address, this);
    dlgreferences.exec();
}

void ListingView::showGoto()
{
    auto* isurface = this->currentISurface();
    if(!isurface) return;

    GotoDialog dlggoto(m_context, isurface, this);
    dlggoto.exec();
}
