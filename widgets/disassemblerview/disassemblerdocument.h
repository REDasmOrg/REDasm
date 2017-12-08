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

    public:
        enum { UnknownBlock = 0,
               Address,
               IsEmptyBlock, IsFunctionBlock, IsInstructionBlock, IsLabelBlock };

        enum { NoAction = 0, GotoAction, XRefAction };

    public:
        explicit DisassemblerDocument(REDasm::Disassembler* disassembler, const QString& theme, QTextDocument *document, QObject* parent = 0);
        QColor highlightColor() const;
        QColor seekColor() const;
        void setTheme(const QString& theme);
        virtual bool generate(address_t address, const QTextCursor &cursor);
        void update(address_t address);

    private:
        void updateInstructions(const REDasm::SymbolPtr &symbol);
        void updateFunction(const REDasm::SymbolPtr &symbol);
        void updateLabels(const REDasm::SymbolPtr &symbol);

    protected:
        virtual void appendFunctionEnd(const REDasm::InstructionPtr &lastinstruction);
        virtual void appendLabel(const REDasm::SymbolPtr& symbol, bool replace = false);
        virtual void appendFunctionStart(const REDasm::SymbolPtr& symbol, bool replace = false);
        virtual void appendInstruction(const REDasm::InstructionPtr& instruction, bool replace = false);
        virtual void appendAddress(const REDasm::InstructionPtr& instruction);
        virtual void appendPathInfo(const REDasm::InstructionPtr &instruction);
        virtual void appendMnemonic(const REDasm::InstructionPtr& instruction);
        virtual void appendComment(const REDasm::InstructionPtr& instruction);
        virtual void appendOperand(const REDasm::Operand& operand, const QString& opstr);

    protected:
        virtual int indentWidth() const;
        int getIndent(address_t address);
        const REDasm::Segment *getSegment(address_t address);
        void setMetaData(QTextCharFormat &charformat, const REDasm::SymbolPtr &symbol, bool showxrefs = false);
        bool selectBlock(address_t address);
        bool isInstructionGenerated(address_t address);

    public:
        static QJsonObject decode(const QString &data);

    protected:
        static QString encode(const QJsonObject &json);

    protected:
        REDasm::Segment* _segment;
        REDasm::Disassembler* _disassembler;
        REDasm::SymbolTable* _symbols;
        GeneratedBlocks _generatedinstructions;
        QTextDocument* _document;
        QTextCursor _textcursor;
        QJsonObject _theme;
};

#endif // DISASSEMBLERDOCUMENT_H
