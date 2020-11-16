#include "listingsplitview.h"
#include "../../hooks/disassemblerhooks.h"
#include "../../themeprovider.h"
#include "../../redasmfonts.h"
#include "listingview.h"

ListingSplitView::ListingSplitView(const RDContextPtr& ctx, QWidget *parent) : SplitView(parent), m_context(ctx)
{
    this->setWindowTitle("Listing");
    this->createFirst();
}

QWidget* ListingSplitView::createWidget() { return new ListingView(m_context, this); }

void ListingSplitView::onItemSplit(const SplitItem* item, const SplitItem* newitem) const
{
    //auto* listing = static_cast<ListingView*>(item->widget());
    //auto* newlisting = static_cast<ListingView*>(newitem->widget());

    //RDDocumentItem docitem;

    //if(listing->textWidget()->getCurrentItem(&docitem))
        //newlisting->textWidget()->goTo(&docitem);
}

void ListingSplitView::onItemCreated(SplitItem* item) const
{
    //auto* listing = static_cast<ListingView*>(item->widget());

    //auto* btnback = item->addButton(FA_ICON_COLOR(0xf053, THEME_VALUE_COLOR(Theme_GraphEdgeLoopCond)));
    //auto* btnforward = item->addButton(FA_ICON_COLOR(0xf054, THEME_VALUE_COLOR(Theme_GraphEdgeLoopCond)));
    //auto* btngoto = item->addButton(FA_ICON(0xf1e5));

    //connect(btnback, &QAction::triggered, listing->textWidget(), [=]() { listing->textWidget()->goBack(); });
    //connect(btnforward, &QAction::triggered, listing->textWidget(), [=]() { listing->textWidget()->goForward(); });
    //connect(btngoto, &QAction::triggered, listing, [=]() { DisassemblerHooks::instance()->showGoto(); });
}
