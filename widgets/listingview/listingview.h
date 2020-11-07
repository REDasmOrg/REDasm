#pragma once

#include <QSplitter>
#include <rdapi/rdapi.h>
#include "listingpathview.h"
#include "listingtextview.h"

class ListingView : public QSplitter
{
    Q_OBJECT

    public:
        explicit ListingView(const RDContextPtr& disassembler, QWidget *parent = nullptr);
        ListingPathView* columnView();
        ListingTextView* textView();

    private:
        RDContextPtr m_context;
        ListingPathView* m_columnview;
        ListingTextView* m_textview;
};
