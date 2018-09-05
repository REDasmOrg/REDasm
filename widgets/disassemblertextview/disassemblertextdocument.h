#ifndef DISASSEMBLERTEXTDOCUMENT_H
#define DISASSEMBLERTEXTDOCUMENT_H

#include "../disassemblerview/disassemblerdocument.h"

class DisassemblerTextDocument : public DisassemblerDocument
{
    Q_OBJECT

    public:
        explicit DisassemblerTextDocument(REDasm::Disassembler* disassembler, QTextDocument *document, QObject* parent = 0);
        void displayRange(size_t start, size_t count);

    private:
        bool isItemRendered(size_t line, REDasm::ListingItem* item);
        void insertItem(QTextCursor &textcursor, REDasm::ListingItem* item);
        void insertSegmentItem(QTextCursor &textcursor, REDasm::ListingItem* item);
        void insertFunctionItem(QTextCursor &textcursor, REDasm::ListingItem* item);
        void insertInstructionItem(QTextCursor &textcursor, REDasm::ListingItem* item);
};

#endif // DISASSEMBLERTEXTDOCUMENT_H
