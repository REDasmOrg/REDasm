#ifndef DISASSEMBLERTEXTDOCUMENT_H
#define DISASSEMBLERTEXTDOCUMENT_H

#include "../disassemblerview/disassemblerdocument.h"

class DisassemblerTextDocument : public DisassemblerDocument
{
    Q_OBJECT

    public:
        explicit DisassemblerTextDocument(REDasm::Disassembler* disassembler, const QString& theme, QTextDocument *document, QObject* parent = 0);
        virtual bool generate(address_t address, const QTextCursor &cursor);

    private:
        void moveToBlock(address_t address);
};

#endif // DISASSEMBLERTEXTDOCUMENT_H
