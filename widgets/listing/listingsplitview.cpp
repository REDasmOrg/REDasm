#include "listingsplitview.h"
#include "../../hooks/disassemblerhooks.h"
#include "../../themeprovider.h"
#include "../../redasmfonts.h"
#include "listingview.h"

ListingSplitView::ListingSplitView(const RDContextPtr& ctx): SplitDockWidget(new ListingView(ctx)), m_context(ctx)
{
    auto* btnback = this->addButton(FA_ICON_COLOR(0xf053, THEME_VALUE_COLOR(Theme_GraphEdgeLoopCond)));
    auto* btnforward = this->addButton(FA_ICON_COLOR(0xf054, THEME_VALUE_COLOR(Theme_GraphEdgeLoopCond)));
    auto* btngoto = this->addButton(FA_ICON(0xf1e5));

    auto* listing = static_cast<ListingView*>(this->splitWidget());
    auto* isurface = listing->currentISurface();
    if(!isurface) return;

    connect(listing, &ListingView::historyChanged, this, &ListingSplitView::checkActions);
    connect(btnback, &QAction::triggered, this, [=]() { isurface->goBack(); });
    connect(btnforward, &QAction::triggered, this, [=]() { isurface->goForward(); });
    connect(btngoto, &QAction::triggered, this, [=]() { listing->showGoto(); });

    this->checkActions();
}

SplitDockWidget* ListingSplitView::createSplit() const
{
    auto* splitview = new ListingSplitView(m_context);
    auto* listing = static_cast<ListingView*>(this->splitWidget());
    auto* newlisting = static_cast<ListingView*>(splitview->splitWidget());

    auto* isurface = listing->currentISurface();
    if(!isurface) return splitview;

    auto* newisurface = newlisting->currentISurface();
    if(!newisurface) return splitview;

    rd_address address = isurface->currentAddress();
    if(address != RD_NVAL) newisurface->seek(address);

    return splitview;
}

void ListingSplitView::checkActions() const
{
    auto* listing = static_cast<ListingView*>(this->splitWidget());
    if(!listing) return;

    auto* isurface = listing->currentISurface();

    this->action(0)->setVisible(isurface);
    this->action(1)->setVisible(isurface);
    this->action(2)->setVisible(isurface);
    this->action(2)->setEnabled(isurface);
    if(!isurface) return;

    this->action(0)->setEnabled(isurface->canGoBack());
    this->action(1)->setEnabled(isurface->canGoForward());
}
