#pragma once

#include <QSplitter>
#include <redasm/disassembler/disassembler.h>
#include "disassemblercolumnview.h"
#include "disassemblertextview.h"

class DisassemblerListingView : public QSplitter
{
    Q_OBJECT

    public:
        explicit DisassemblerListingView(QWidget *parent = nullptr);
        ~DisassemblerListingView();
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
