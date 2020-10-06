#pragma once

#include <QSplitter>
#include <rdapi/rdapi.h>
#include "disassemblercolumnview.h"
#include "disassemblertextview.h"

class DisassemblerListingView : public QSplitter
{
    Q_OBJECT

    public:
        explicit DisassemblerListingView(const RDContextPtr& disassembler, QWidget *parent = nullptr);
        DisassemblerColumnView* columnView();
        DisassemblerTextView* textView();

    private:
        RDContextPtr m_context;
        DisassemblerColumnView* m_columnview;
        DisassemblerTextView* m_textview;
};
