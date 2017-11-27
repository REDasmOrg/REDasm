#include "disassemblerdocument.h"
#include <QJsonDocument>
#include <QVariant>
#include <QFile>
#include <QDebug>

#define THEME_VALUE_S(name) (this->_theme.contains(name) ? this->_theme[name].toString() : QString())
#define HEX_ADDRESS(address) S_TO_QS(REDasm::hex(address, this->_disassembler->format()->bits()))
#define HEX_ADDRESS_NP(address) S_TO_QS(REDasm::hex(address, this->_disassembler->format()->bits(), false))
#define HEX_ADDRESS_NO_BITS(address) S_TO_QS(REDasm::hex(address))
#define ADDRESS_VARIANT(address) QJsonValue::fromVariant(QVariant::fromValue(address))

#define INDENT_COMMENT 10
#define INDENT_WIDTH 2

DisassemblerDocument::DisassemblerDocument(REDasm::Disassembler *disassembler): QDomDocument(), _currentsymbol(NULL), _disassembler(disassembler), _symbols(disassembler->symbols())
{

}

const REDasm::Symbol *DisassemblerDocument::currentFunction() const
{
    return this->_currentsymbol;
}

QColor DisassemblerDocument::lineColor() const
{
    return QColor(THEME_VALUE_S("line"));
}

int DisassemblerDocument::lineFromAddress(address_t address) const
{
    int index = -1;
    this->getDisassemblerElement("instruction", address, &index);
    return index;
}

void DisassemblerDocument::setTheme(const QString &theme)
{
    QFile f(QString(":/themes/%1.json").arg(theme));

    if(!f.open(QFile::ReadOnly))
    {
        qWarning("Cannot load '%s' theme", qUtf8Printable(theme));
        return;
    }

    QJsonDocument doc = QJsonDocument::fromJson(f.readAll());

    if(doc.isObject())
        this->_theme = doc.object();

    f.close();
}

void DisassemblerDocument::populate()
{
    REDasm::Listing& listing = this->_disassembler->listing();
    this->clear();

    listing.iterateAll([this](const REDasm::InstructionPtr& i) { this->appendChild(this->createInstructionElement(i)); },
                       [this](const REDasm::Symbol* s) { this->appendChild(this->createFunctionElement(s)); },
                       [this](const REDasm::Symbol*)   { this->appendChild(this->createEmptyElement()); },
                       [this](const REDasm::Symbol* s) { this->appendChild(this->createLabelElement(s)); });
}

QDomElement DisassemblerDocument::getDisassemblerElement(const QString &type, address_t address, int *index, QDomElement& e) const
{
    bool found = false;
    int i = 0;

    if(e.isNull())
        e = this->firstChildElement();

    for(; !e.isNull(); e = e.nextSiblingElement(), i++)
    {
        if((e.attribute("type") != type) || !e.hasAttribute("address"))
            continue;

        bool ok = false;
        address_t elmaddress = e.attribute("address").toULongLong(&ok, 16);

        if(!ok || (address != elmaddress))
            continue;

        found = true;
        break;
    }

    if(index)
        *index = found ? i : -1;

    return e;
}

QDomElement DisassemblerDocument::getDisassemblerElement(const QString &type, address_t address, QDomElement &e) const
{
    return this->getDisassemblerElement(type, address, NULL, e);
}

QDomElement DisassemblerDocument::getDisassemblerElement(const QString &type, address_t address, int *index) const
{
    QDomElement e;
    return this->getDisassemblerElement(type, address, index, e);
}

QDomNode DisassemblerDocument::createGotoElement(const REDasm::Symbol *symbol, bool showxrefs)
{
    return this->createGotoElement(symbol, S_TO_QS(symbol->name), showxrefs);
}

QDomNode DisassemblerDocument::createGotoElement(const REDasm::Symbol* symbol, const QString &label, bool showxrefs)
{
    QJsonObject data = { { "action", DisassemblerDocument::XRefAction },
                         { "address", ADDRESS_VARIANT(symbol->address) } };

    if(symbol->is(REDasm::SymbolTypes::Code))
    {
        if(!showxrefs)
            data["action"] = DisassemblerDocument::GotoAction;

        return this->createAnchorElement(label, data, THEME_VALUE_S("function_fg"));
    }
    else if(symbol->is(REDasm::SymbolTypes::String))
        return this->createAnchorElement(label, data, THEME_VALUE_S("string_fg"));

    return this->createAnchorElement(label, data, THEME_VALUE_S("data_fg"));
}

QDomNode DisassemblerDocument::createAnchorElement(const QString& label, const QJsonObject data, const QString& color)
{
    return this->createAnchorElement(this->createTextNode(label), data, color);
}

QDomNode DisassemblerDocument::createAnchorElement(const QDomNode &n, const QJsonObject data, const QString& color)
{
    QDomElement e = this->createElement("a");
    e.setAttribute("href", (!data.isEmpty() ? DisassemblerDocument::encode(data) : "#"));

    if(!color.isEmpty())
        e.setAttribute("style", QString("color: %1").arg(color));

    e.appendChild(n);
    return e;
}

QDomNode DisassemblerDocument::createInfoElement(address_t address, const QDomNode& node, const QString &type)
{
    QDomElement e = this->createElement("div");
    REDasm::FormatPlugin* format = this->_disassembler->format();
    const REDasm::Segment* segment = format->segment(address);
    int width = format->bits() / 4;

    if(segment)
        width += segment->name.length();

    if(!type.isEmpty())
        e.setAttribute("type", type);

    e.setAttribute("address", HEX_ADDRESS(address));
    e.appendChild(this->createTextNode(QString("\u00A0").repeated(width + INDENT_WIDTH)));
    e.appendChild(node);
    return e;
}

QDomNode DisassemblerDocument::createAddressElement(const REDasm::InstructionPtr &instruction)
{
    QString address;
    REDasm::FormatPlugin* format = this->_disassembler->format();
    const REDasm::Segment* segment = format->segment(instruction->address);

    if(segment)
        address = S_TO_QS(segment->name);
    else
        address = "unk";

    address += ":" + HEX_ADDRESS_NP(instruction->address);

    QDomElement e = this->createElement("font");
    e.setAttribute("color", THEME_VALUE_S("address_fg"));
    e.appendChild(this->createTextNode(address));
    return e;
}

QDomNode DisassemblerDocument::createInstructionElement(const REDasm::InstructionPtr &instruction)
{
    QDomElement elminstruction = this->createElement("div");
    elminstruction.setAttribute("address", HEX_ADDRESS(instruction->address));
    elminstruction.setAttribute("type", "instruction");
    elminstruction.appendChild(this->createAddressElement(instruction));
    elminstruction.appendChild(this->createTextNode("\u00A0\u00A0"));
    elminstruction.appendChild(this->createMnemonicElement(instruction));
    elminstruction.appendChild(this->createTextNode("\u00A0"));

    this->_disassembler->out(instruction, [this, &elminstruction](const REDasm::Operand& operand, const std::string& opstr) {
        if(operand.index > 0)
            elminstruction.appendChild(this->createTextNode(", "));

        elminstruction.appendChild(this->createOperandElement(operand, S_TO_QS(opstr)));
    });

    elminstruction.appendChild(this->createCommentElement(instruction));
    return elminstruction;
}

QDomNode DisassemblerDocument::createMnemonicElement(const REDasm::InstructionPtr &instruction)
{
    QDomText elmmnemonic = this->createTextNode(S_TO_QS(instruction->mnemonic));

    if(!instruction->type)
        return elmmnemonic;

    QDomElement e = this->createElement("font");

    if(instruction->isInvalid())
        e.setAttribute("color", THEME_VALUE_S("instruction_invalid"));
    else if(instruction->is(REDasm::InstructionTypes::Stop))
        e.setAttribute("color", THEME_VALUE_S("instruction_stop"));
    else if(instruction->is(REDasm::InstructionTypes::Nop))
        e.setAttribute("color", THEME_VALUE_S("instruction_nop"));
    else if(instruction->is(REDasm::InstructionTypes::Call))
        e.setAttribute("color", THEME_VALUE_S("instruction_call"));
    else if(instruction->is(REDasm::InstructionTypes::Jump))
    {
        if(instruction->is(REDasm::InstructionTypes::Conditional))
            e.setAttribute("color", THEME_VALUE_S("instruction_jmp_c"));
        else
            e.setAttribute("color", THEME_VALUE_S("instruction_jmp"));
    }

    e.appendChild(elmmnemonic);
    return e;
}

QDomNode DisassemblerDocument::createCommentElement(const REDasm::InstructionPtr &instruction)
{
    if(instruction->comments.empty())
        return QDomNode();

    QDomElement e = this->createElement("font");
    e.setAttribute("color", THEME_VALUE_S("comment_fg"));
    e.appendChild(this->createTextNode(QString("\u00A0").repeated(INDENT_COMMENT) + S_TO_QS(this->_disassembler->comment(instruction))));
    return e;
}

QDomNode DisassemblerDocument::createOperandElement(const REDasm::Operand &operand, const QString& opstr)
{
    QDomElement e = this->createElement("font");
    e.appendChild(this->createTextNode(opstr));

    if(operand.is(REDasm::OperandTypes::Immediate) || operand.is(REDasm::OperandTypes::Memory))
    {
        REDasm::Symbol* symbol = this->_symbols->symbol(operand.is(REDasm::OperandTypes::Immediate) ? operand.s_value :
                                                                                                      operand.u_value);

        if(symbol)
        {
            if(symbol->is(REDasm::SymbolTypes::Pointer))
            {
                REDasm::Symbol* ptrsymbol = this->_disassembler->dereferenceSymbol(symbol);

                if(ptrsymbol)
                    symbol = ptrsymbol;
            }

            e = this->createGotoElement(symbol, opstr).toElement();
        }
        else
            e.setAttribute("color", operand.is(REDasm::OperandTypes::Immediate) ? THEME_VALUE_S("immediate_fg") :
                                                                                  THEME_VALUE_S("memory_fg"));
    }
    else if(operand.is(REDasm::OperandTypes::Displacement))
    {
        REDasm::Symbol* symbol = this->_symbols->symbol(operand.mem.displacement);

        if(symbol)
            e = this->createGotoElement(symbol, opstr, !operand.mem.displacementOnly()).toElement();
        else
            e.setAttribute("color", THEME_VALUE_S("displacement_fg"));
    }
    else if(operand.is(REDasm::OperandTypes::Register))
        e.setAttribute("color", THEME_VALUE_S("register_fg"));

    return e;
}

QDomNode DisassemblerDocument::createFunctionElement(const REDasm::Symbol* symbol)
{
    QDomElement f = this->createElement("font");
    f.setAttribute("address", HEX_ADDRESS(symbol->address));
    f.setAttribute("color", THEME_VALUE_S("function_fg"));
    f.appendChild(this->createTextNode(QString("=").repeated(20) + " "));
    f.appendChild(this->createTextNode("FUNCTION "));
    f.appendChild(this->createGotoElement(symbol, true));
    f.appendChild(this->createTextNode(" " + QString("=").repeated(20)));

    return this->createInfoElement(symbol->address, f, "function_start");
}

QDomNode DisassemblerDocument::createEmptyElement()
{
    QDomElement e = this->createElement("div");
    e.appendChild(this->createTextNode("\u00A0"));
    return e;
}

QDomNode DisassemblerDocument::createLabelElement(const REDasm::Symbol *symbol)
{
    QJsonObject data = { { "action", DisassemblerDocument::XRefAction },
                         { "address", ADDRESS_VARIANT(symbol->address) } };

    QString addrstring = HEX_ADDRESS(symbol->address);
    QDomNode a = this->createAnchorElement(S_TO_QS(symbol->name) + ":", data, THEME_VALUE_S("label_fg"));
    QDomElement e = this->createInfoElement(symbol->address, a, "label").toElement();

    e.setAttribute("address", addrstring);
    return e;
}

QJsonObject DisassemblerDocument::decode(const QString &data)
{
    QJsonDocument doc = QJsonDocument::fromJson(QByteArray::fromBase64(data.toUtf8()));
    return doc.object();
}

QString DisassemblerDocument::encode(const QJsonObject& json)
{
    QJsonDocument doc(json);
    return doc.toJson().toBase64();
}
