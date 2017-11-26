#ifndef DISASSEMBLERDOCUMENT_H
#define DISASSEMBLERDOCUMENT_H

#include <QDomDocument>
#include <QJsonObject>
#include <QColor>
#include <QHash>
#include <QUrl>
#include "../../redasm/disassembler/disassembler.h"

#define S_TO_QS(s) QString::fromStdString(s)

class DisassemblerDocument: public QDomDocument
{
    public:
        enum
        {
            NoAction = 0,
            GotoAction,
            XRefAction
        };

    public:
        DisassemblerDocument(REDasm::Disassembler* disassembler);
        const REDasm::Symbol* currentFunction() const;
        QColor lineColor() const;
        int lineFromAddress(address_t address) const;
        void setTheme(const QString& theme);
        void populate();

    private:
        QDomElement getDisassemblerElement(const QString& type, address_t address, int* index, QDomElement &e) const;
        QDomElement getDisassemblerElement(const QString& type, address_t address, QDomElement &e) const;
        QDomElement getDisassemblerElement(const QString& type, address_t address, int* index = NULL) const;
        QDomNode createGotoElement(const REDasm::Symbol *symbol, bool showxrefs = false);
        QDomNode createGotoElement(const REDasm::Symbol *symbol, const QString& label, bool showxrefs = false);
        QDomNode createAnchorElement(const QString &label, const QJsonObject data = QJsonObject(), const QString& color = QString());
        QDomNode createAnchorElement(const QDomNode& n, const QJsonObject data = QJsonObject(), const QString &color = QString());
        QDomNode createInfoElement(address_t address, const QDomNode &node, const QString& type);
        QDomNode createAddressElement(const REDasm::InstructionPtr &instruction);
        QDomNode createInstructionElement(const REDasm::InstructionPtr &instruction);
        QDomNode createMnemonicElement(const REDasm::InstructionPtr &instruction);
        QDomNode createCommentElement(const REDasm::InstructionPtr &instruction);
        QDomNode createOperandElement(const REDasm::Operand& operand, const QString &opstr);
        QDomNode createFunctionElement(const REDasm::Symbol *symbol);
        QDomNode createEmptyElement();
        QDomNode createLabelElement(const REDasm::Symbol *symbol);

    public:
        static QJsonObject decode(const QString &data);

    private:
        static QString encode(const QJsonObject &json);

    private:
        const REDasm::Symbol* _currentsymbol;
        REDasm::Disassembler* _disassembler;
        REDasm::SymbolTable* _symbols;
        QJsonObject _theme;
};

#endif // DISASSEMBLERDOCUMENT_H
