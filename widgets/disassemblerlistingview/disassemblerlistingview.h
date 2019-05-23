#ifndef DISASSEMBLERLISTINGVIEW_H
#define DISASSEMBLERLISTINGVIEW_H

#include <QSplitter>
#include <core/disassembler/disassemblerapi.h>
#include "disassemblercolumnview.h"
#include "disassemblertextview.h"

class DisassemblerListingView : public QSplitter
{
    Q_OBJECT

    public:
        explicit DisassemblerListingView(QWidget *parent = nullptr);
        DisassemblerColumnView* columnView();
        DisassemblerTextView* textView();
        void setDisassembler(const REDasm::DisassemblerPtr &disassembler);

    private slots:
        void renderArrows();

    private:
        REDasm::DisassemblerPtr m_disassembler;
        DisassemblerColumnView* m_disassemblercolumnview;
        DisassemblerTextView* m_disassemblertextview;
};

#endif // DISASSEMBLERLISTINGVIEW_H
