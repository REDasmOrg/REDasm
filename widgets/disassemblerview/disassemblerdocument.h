#ifndef DISASSEMBLERDOCUMENT_H
#define DISASSEMBLERDOCUMENT_H

#include <QTextDocument>
#include <QTextCursor>
#include <QTextBlock>
#include <QJsonObject>
#include <QColor>
#include <QUrl>
#include "../../redasm/disassembler/disassembler.h"

#define S_TO_QS(s)           QString::fromStdString(s)
#define HEX_ADDRESS(address) S_TO_QS(REDasm::hex(address, this->_disassembler->format()->bits(), false))

class DisassemblerDocument: public QObject
{
    Q_OBJECT

    private:
        typedef std::set<address_t> GeneratedBlocks;
        typedef std::set<address_t> PendingSymbols;

    public:
        enum { UnknownBlock = 0,
               Address,
               IsEmptyBlock, IsFunctionBlock, IsInstructionBlock, IsLabelBlock, IsSymbolBlock };

        enum { NoAction = 0, GotoAction, LabelAction };

    public:
        explicit DisassemblerDocument(REDasm::Disassembler* disassembler, const QString& theme, QTextDocument *document, QObject* parent = 0);
        QColor highlightColor() const;
        QColor seekColor() const;
        QColor dottedColor() const;
        void setTheme(const QString& theme);
        virtual bool generate(address_t address, const QTextCursor &cursor);
        void update(address_t address);

    private:
        void updateInstructions(const REDasm::SymbolPtr &symbol);
        void updateFunction(const REDasm::SymbolPtr &symbol);
        void updateLabels(const REDasm::SymbolPtr &symbol);
        void updateSymbol(const REDasm::SymbolPtr &symbol);

    protected:
        virtual void appendEmpty(address_t address);
        virtual void appendLabel(const REDasm::SymbolPtr& symbol, bool replace = false);
        virtual void appendFunctionStart(const REDasm::SymbolPtr& symbol, bool replace = false);
        virtual void appendInstruction(const REDasm::InstructionPtr& instruction, bool replace = false);
        virtual void appendOperands(const REDasm::InstructionPtr& instruction);
        virtual REDasm::SymbolPtr appendOperand(const REDasm::Operand& operand, const QString &opsize, const QString& opstr);
        virtual void appendAddress(address_t address);
        virtual void appendPathInfo(const REDasm::InstructionPtr &instruction);
        virtual void appendMnemonic(const REDasm::InstructionPtr& instruction);
        virtual void appendComment(const REDasm::InstructionPtr& instruction);
        virtual void appendInfo(address_t address, const QString& info);
        virtual void appendSymbol(const REDasm::SymbolPtr& symbol, const std::string &value, bool replace = false);
        virtual void appendSymbols(bool replace = false);

    protected:
        virtual int indentWidth() const;
        int getIndent(address_t address);
        const REDasm::Segment *getSegment(address_t address);
        void setCurrentPrinter(const REDasm::PrinterPtr& printer);
        void setMetaData(QTextCharFormat &charformat, const REDasm::SymbolPtr &symbol);
        bool selectBlock(address_t address);
        void moveToBlock(address_t address);
        bool isInstructionGenerated(address_t address);

    public:
        static QJsonObject decode(const QString &data);

    protected:
        static QString encode(const QJsonObject &json);

    protected:
        REDasm::Segment* _segment;
        REDasm::Disassembler* _disassembler;
        REDasm::SymbolTable* _symbols;
        REDasm::PrinterPtr _currentprinter, _printer;
        GeneratedBlocks _generatedblocks;
        PendingSymbols _pendingsymbols;
        QTextDocument* _document;
        QTextCursor _textcursor;
        QJsonObject _theme;
};

#endif // DISASSEMBLERDOCUMENT_H
