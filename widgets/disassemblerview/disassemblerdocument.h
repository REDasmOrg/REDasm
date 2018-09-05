#ifndef DISASSEMBLERDOCUMENT_H
#define DISASSEMBLERDOCUMENT_H

#include <QTextDocument>
#include <QTextCursor>
#include <QTextBlock>
#include <QColor>
#include <QUrl>
#include "../../redasm/disassembler/disassembler.h"
#include "../../themeprovider.h"

#define S_TO_QS(s)           QString::fromStdString(s)
#define HEX_ADDRESS(address) S_TO_QS(REDasm::hex(address, m_disassembler->format()->bits(), false))

class DisassemblerDocument: public QObject
{
    Q_OBJECT

    private:
        typedef std::set<address_t> GeneratedBlocks;
        typedef std::set<address_t> PendingAddresses;

    public:
        enum { UnknownBlock = QTextFormat::UserProperty + 1,
               Address,
               Item,
               IsEmptyBlock, IsSegmentBlock, IsFunctionBlock, IsInstructionBlock, IsLabelBlock, IsSymbolBlock };

        enum { NoAction = 0, GotoAction, LabelAction };

    public:
        explicit DisassemblerDocument(REDasm::Disassembler* disassembler, QTextDocument *document, QObject* parent = 0);
        virtual bool generate(address_t address, const QTextCursor &cursor);
        void update(address_t address);

    private:
        void updateInstructions(const REDasm::SymbolPtr &symbol);
        void updateFunction(const REDasm::SymbolPtr &symbol);
        void updateLabels(const REDasm::SymbolPtr &symbol);
        void updateSymbol(const REDasm::SymbolPtr &symbol);

    protected:
        void insertIndent(QTextCursor &textcursor, address_t address, int extraindent = 0);
        virtual void appendEmpty(address_t address);
        virtual void appendLabel(const REDasm::SymbolPtr& symbol, bool replace = false);
        virtual void appendFunctionStart(const REDasm::SymbolPtr& symbol, bool replace = false);
        virtual void insertInstruction(QTextCursor &textcursor, const REDasm::InstructionPtr& instruction);
        virtual void insertOperands(QTextCursor& textcursor, const REDasm::InstructionPtr& instruction);
        virtual void insertOperand(QTextCursor &textcursor, const REDasm::InstructionPtr &instruction, const REDasm::Operand& operand, const QString &opsize, const QString& opstr);
        virtual void insertAddress(QTextCursor& textcursor, address_t address);
        virtual void appendPathInfo(const REDasm::InstructionPtr &instruction);
        virtual void insertMnemonic(QTextCursor &textcursor, const REDasm::InstructionPtr& instruction);
        virtual void insertComment(QTextCursor& textcursor, const REDasm::InstructionPtr& instruction);
        virtual void appendInfo(address_t address, const QString& info);
        virtual void appendSymbol(const REDasm::SymbolPtr& symbol, const std::string &value, bool replace = false);
        virtual void appendSymbols(bool replace = false);

    protected:
        int getIndent(address_t address);
        void setCurrentPrinter(const REDasm::PrinterPtr& printer);
        void setMetaData(QTextCharFormat &charformat, const REDasm::SymbolPtr &symbol);
        bool selectBlock(address_t address);
        void moveToBlock(address_t address);
        bool isBlockGenerated(address_t address);

    public:
        static QJsonObject decode(const QString &data);

    protected:
        static QString encode(const QJsonObject &json);

    protected:
        REDasm::Segment* m_segment;
        REDasm::Disassembler* m_disassembler;
        REDasm::SymbolTable* _symbols;
        REDasm::PrinterPtr _currentprinter, m_printer;
        GeneratedBlocks _generatedblocks;
        PendingAddresses _pendingsymbols, _pendinginstructions;
        QTextDocument* m_textdocument;
        QTextCursor _textcursor;
};

#endif // DISASSEMBLERDOCUMENT_H
