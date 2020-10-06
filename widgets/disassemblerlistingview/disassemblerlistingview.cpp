#include "disassemblerlistingview.h"
#include "../../themeprovider.h"
#include "../../redasmsettings.h"

DisassemblerListingView::DisassemblerListingView(const RDContextPtr& ctx, QWidget *parent): QSplitter(Qt::Horizontal, parent), m_context(ctx)
{
    this->setStyleSheet("QSplitter::handle { background-color: " + THEME_VALUE_COLOR(Theme_Seek) + "; }");

    m_textview = new DisassemblerTextView(this);
    m_textview->setFont(REDasmSettings::font());
    m_textview->setContext(ctx);

    m_columnview = new DisassemblerColumnView(this);
    m_columnview->setFont(m_textview->font()); // Apply same font
    m_columnview->linkTo(m_textview);

    this->addWidget(m_columnview);
    this->addWidget(m_textview);

    this->setStretchFactor(0, 2);
    this->setStretchFactor(1, 10);
    this->setHandleWidth(4);
}

DisassemblerColumnView *DisassemblerListingView::columnView() { return m_columnview; }
DisassemblerTextView *DisassemblerListingView::textView() { return m_textview; }
