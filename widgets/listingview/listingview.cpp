#include "listingview.h"
#include "../../themeprovider.h"
#include "../../redasmsettings.h"

ListingView::ListingView(const RDContextPtr& ctx, QWidget *parent): QSplitter(Qt::Horizontal, parent), m_context(ctx)
{
    this->setStyleSheet("QSplitter::handle { background-color: " + THEME_VALUE_COLOR(Theme_Seek) + "; }");

    m_textview = new ListingTextView(this);
    m_textview->setFont(REDasmSettings::font());
    m_textview->setContext(ctx);

    m_columnview = new ListingPathView(this);
    m_columnview->setFont(m_textview->font()); // Apply same font
    m_columnview->linkTo(m_textview);

    this->addWidget(m_columnview);
    this->addWidget(m_textview);

    this->setStretchFactor(0, 2);
    this->setStretchFactor(1, 10);
    this->setHandleWidth(4);
}

ListingPathView *ListingView::columnView() { return m_columnview; }
ListingTextView *ListingView::textView() { return m_textview; }
