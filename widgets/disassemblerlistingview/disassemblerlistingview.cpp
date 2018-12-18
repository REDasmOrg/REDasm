#include "disassemblerlistingview.h"
#include "../../themeprovider.h"
#include <QScrollBar>

DisassemblerListingView::DisassemblerListingView(QWidget *parent): QSplitter(parent), m_disassembler(NULL)
{
    this->setOrientation(Qt::Horizontal);
    this->setStyleSheet("QSplitter::handle { background-color: " + THEME_VALUE_COLOR("seek") + "; }");

    m_disassemblertextview = new DisassemblerTextView(this);
    m_disassemblercolumnview = new DisassemblerColumnView(this);
    m_disassemblercolumnview->setFont(m_disassemblertextview->font()); // Apply same font

    connect(m_disassemblertextview->verticalScrollBar(), &QScrollBar::valueChanged, [&](int) { this->renderArrows(); });

    this->addWidget(m_disassemblercolumnview);
    this->addWidget(m_disassemblertextview);

    this->setStretchFactor(0, 2);
    this->setStretchFactor(1, 10);
    this->setHandleWidth(4);
}

DisassemblerColumnView *DisassemblerListingView::columnView() { return m_disassemblercolumnview; }
DisassemblerTextView *DisassemblerListingView::textView() { return m_disassemblertextview; }

void DisassemblerListingView::setDisassembler(REDasm::DisassemblerAPI *disassembler)
{
    m_disassembler = disassembler;
    m_disassemblercolumnview->setDisassembler(disassembler);
    m_disassemblertextview->setDisassembler(disassembler);

    REDasm::ListingDocument* document = m_disassembler->document();

    document->cursor()->positionChanged += [&]() {
        QMetaObject::invokeMethod(m_disassemblercolumnview, "update", Qt::QueuedConnection);
    };

    m_disassembler->busyChanged += [&]() {
        if(m_disassembler->busy())
            return;

        QMetaObject::invokeMethod(this, "renderArrows", Qt::QueuedConnection);
    };
}

void DisassemblerListingView::renderArrows()
{
    if(m_disassembler->busy())
        return;

    m_disassemblercolumnview->renderArrows(m_disassemblertextview->firstVisibleLine(), m_disassemblertextview->visibleLines());
}
