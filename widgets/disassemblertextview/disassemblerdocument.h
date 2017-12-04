#ifndef DISASSEMBLERDOCUMENT_H
#define DISASSEMBLERDOCUMENT_H

#include <QTextDocument>
#include <QTextCursor>
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
        typedef std::map<address_t, address_t> GeneratedFunctions;

    public:
        enum { UnknownBlock = 0,
               Address,
               IsEmptyBlock, IsFunctionBlock, IsInstructionBlock, IsLabelBlock };

        enum { NoAction = 0, GotoAction, XRefAction };

    public:
        DisassemblerDocument(REDasm::Disassembler* disassembler, const QString& theme, QTextDocument *document, const QTextCursor &cursor, QObject* parent = 0);
        QColor highlightColor() const;
        QColor seekColor() const;
        void setTheme(const QString& theme);
        void generate(address_t address, const QTextCursor &cursor);

    private:
        void appendEmpty(const REDasm::SymbolPtr& symbol);
        void appendLabel(const REDasm::SymbolPtr& symbol);
        void appendFunction(const REDasm::SymbolPtr& symbol);
        void appendInstruction(const REDasm::InstructionPtr& instruction);
        void appendAddress(const REDasm::InstructionPtr& instruction);
        void appendMnemonic(const REDasm::InstructionPtr& instruction);
        void appendComment(const REDasm::InstructionPtr& instruction);
        void appendOperand(const REDasm::Operand& operand, const QString& opstr);

    private:
        int getIndent(address_t address);
        const REDasm::Segment *getSegment(address_t address);
        void setMetaData(QTextCharFormat &charformat, const REDasm::SymbolPtr &symbol, bool showxrefs = false);
        void selectBlock(address_t address);
        bool isGenerated(address_t address);

    public:
        static QJsonObject decode(const QString &data);

    private:
        static QString encode(const QJsonObject &json);

    private:
        REDasm::Segment* _segment;
        REDasm::Disassembler* _disassembler;
        REDasm::SymbolTable* _symbols;
        GeneratedFunctions _generated;
        QTextDocument* _document;
        QTextCursor _textcursor;
        QJsonObject _theme;
};

#endif // DISASSEMBLERDOCUMENT_H
