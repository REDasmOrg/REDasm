#include "listingsplitview.h"
#include "../../hooks/disassemblerhooks.h"
#include "../../themeprovider.h"
#include "../../redasmfonts.h"
#include "listingview.h"
#include <QDebug>

ListingSplitView::ListingSplitView(const RDContextPtr& ctx, QWidget *parent) : SplitView(parent), m_context(ctx)
{
    this->setWindowTitle("Listing");
    this->createFirst();
}

SplitView* ListingSplitView::createView() const { return new ListingSplitView(m_context); }
QWidget* ListingSplitView::createWidget() { return new ListingView(m_context, this); }

void ListingSplitView::onItemSplit(SplitItem* item, SplitItem* newitem)
{
    SplitView::onItemSplit(item, newitem);

    auto* listing = static_cast<ListingView*>(item->widget());
    auto* newlisting = static_cast<ListingView*>(newitem->widget());

    auto* isurface = listing->currentISurface();
    if(!isurface) return;

    auto* newisurface = newlisting->currentISurface();
    if(!newisurface) return;

    RDDocumentItem docitem;
    if(isurface->getCurrentItem(&docitem)) newisurface->goTo(&docitem);
}

void ListingSplitView::onItemCreated(SplitItem* item)
{
    SplitView::onItemCreated(item);

    auto* listing = static_cast<ListingView*>(item->widget());
    auto* isurface = listing->currentISurface();
    if(!isurface) return;

    auto* btnback = item->addButton(FA_ICON_COLOR(0xf053, THEME_VALUE_COLOR(Theme_GraphEdgeLoopCond)));
    auto* btnforward = item->addButton(FA_ICON_COLOR(0xf054, THEME_VALUE_COLOR(Theme_GraphEdgeLoopCond)));
    auto* btngoto = item->addButton(FA_ICON(0xf1e5));

    this->checkActions(listing);

    connect(listing, &ListingView::historyChanged, item, [=]() { this->checkActions(listing); });
    connect(btnback, &QAction::triggered, item, [=]() { isurface->goBack(); });
    connect(btnforward, &QAction::triggered, item, [=]() { isurface->goForward(); });
    connect(btngoto, &QAction::triggered, item, [=]() { listing->showGoto(); });
}

void ListingSplitView::checkActions(ListingView* listing) const
{
    auto* splititem = this->splitItem(listing);
    if(!splititem) return;
    auto* isurface = listing->currentISurface();
    if(!isurface) return;

    splititem->action(0)->setVisible(isurface);
    splititem->action(1)->setVisible(isurface);
    splititem->action(2)->setVisible(isurface);
    splititem->action(2)->setEnabled(isurface);
    if(!isurface) return;

    splititem->action(0)->setEnabled(isurface->canGoBack());
    splititem->action(1)->setEnabled(isurface->canGoForward());
}
