#include "disassemblerlistingview.h"
#include "../../themeprovider.h"
#include "../../redasmsettings.h"

DisassemblerListingView::DisassemblerListingView(RDDisassembler* disassembler, QWidget *parent): QSplitter(Qt::Horizontal, parent), m_disassembler(nullptr)
{
    this->setStyleSheet("QSplitter::handle { background-color: " + THEME_VALUE_COLOR("seek") + "; }");

    m_disassemblertextview = new DisassemblerTextView(this);
    m_disassemblertextview->setFont(REDasmSettings::font());
    m_disassemblertextview->setDisassembler(disassembler);

    m_disassemblercolumnview = new DisassemblerColumnView(this);
    m_disassemblercolumnview->setFont(m_disassemblertextview->font()); // Apply same font

    this->addWidget(m_disassemblercolumnview);
    this->addWidget(m_disassemblertextview);

    this->setStretchFactor(0, 2);
    this->setStretchFactor(1, 10);
    this->setHandleWidth(4);
}

DisassemblerColumnView *DisassemblerListingView::columnView() { return m_disassemblercolumnview; }
DisassemblerTextView *DisassemblerListingView::textView() { return m_disassemblertextview; }

void DisassemblerListingView::setDisassembler(RDDisassembler* disassembler)
{
    m_disassembler = disassembler;
    m_disassemblertextview->setDisassembler(m_disassembler);
    m_disassemblercolumnview->linkTo(m_disassemblertextview);
}
