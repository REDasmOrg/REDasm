#pragma once

#include <QSplitter>
#include <rdapi/rdapi.h>
#include "disassemblercolumnview.h"
#include "listingtextview.h"

class DisassemblerListingView : public QSplitter
{
    Q_OBJECT

    public:
        explicit DisassemblerListingView(const RDContextPtr& disassembler, QWidget *parent = nullptr);
        DisassemblerColumnView* columnView();
        ListingTextView* textView();

    private:
        RDContextPtr m_context;
        DisassemblerColumnView* m_columnview;
        ListingTextView* m_textview;
};
