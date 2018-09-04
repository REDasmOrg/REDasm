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
        bool isBlockRendered(size_t line, REDasm::ListingItem* block);
        void insertBlock(QTextCursor &textcursor, REDasm::ListingItem* block);
        void insertSegment(QTextCursor &textcursor, REDasm::ListingItem* block);
        void insertFunction(QTextCursor &textcursor, REDasm::ListingItem* block);
};

#endif // DISASSEMBLERTEXTDOCUMENT_H
