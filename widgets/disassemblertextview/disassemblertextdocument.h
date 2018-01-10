#ifndef DISASSEMBLERTEXTDOCUMENT_H
#define DISASSEMBLERTEXTDOCUMENT_H

#include "../disassemblerview/disassemblerdocument.h"
#include "../../redasm/vmil/vmil_printer.h"

class DisassemblerTextDocument : public DisassemblerDocument
{
    Q_OBJECT

    public:
        explicit DisassemblerTextDocument(REDasm::Disassembler* disassembler, const QString& theme, QTextDocument *document, QObject* parent = 0);
        virtual bool generate(address_t address, const QTextCursor &cursor);
        bool generateVMIL(address_t address, const QTextCursor& cursor);

    private:
        bool _isvmil;
        REDasm::VMIL::VMILPrinterPtr _vmilprinter;
};

#endif // DISASSEMBLERTEXTDOCUMENT_H
