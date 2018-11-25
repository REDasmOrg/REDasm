#include "listingrenderer.h"
#include "../../plugins/assembler/assembler.h"
#include "../../plugins/format.h"

#define INDENT_WIDTH         2
#define INDENT_COMMENT       10
#define HEX_ADDRESS(address) REDasm::hex(address, m_disassembler->format()->bits())

namespace REDasm {

ListingRenderer::ListingRenderer(DisassemblerAPI *disassembler): m_flags(ListingRenderer::Normal), m_disassembler(disassembler)
{
    m_document = disassembler->document();
    m_cursor = m_document->cursor();
    m_printer = PrinterPtr(disassembler->assembler()->createPrinter(disassembler));
}

void ListingRenderer::render(u64 start, u64 count, void *userdata)
{
    ListingCursor* cur = m_document->cursor();
    u64 end = start + count, line = start;

    for(u64 i = 0; line < std::min(m_document->size(), end); i++, line++)
    {
        RendererLine rl;
        rl.userdata = userdata;
        rl.line = line;
        rl.index = i;
        rl.highlighted = cur->currentLine() == line;

        this->getRendererLine(line, rl);
        this->renderLine(rl);
    }
}

u64 ListingRenderer::getLastColumn(u64 line)
{
    RendererLine rl;
    this->getRendererLine(line, rl);
    u64 len = static_cast<u64>(rl.length());

    if(!len)
        return 0;

    return len - 1;
}

std::string ListingRenderer::getLine(u64 line)
{
    RendererLine rl;
    this->getRendererLine(line, rl);
    return rl.text;
}

std::string ListingRenderer::getSelectedText()
{
    const ListingCursor* cur = m_document->cursor();

    if(!cur->hasSelection())
        return std::string();

    const ListingCursor::Position& startpos = cur->startSelection();
    const ListingCursor::Position& endpos = cur->endSelection();

    std::string copied;

    if(startpos.first != endpos.first)
    {
        u64 line = startpos.first;

        while(line <= endpos.first)
        {
            RendererLine rl;
            this->getRendererLine(line, rl);
            std::string s = rl.text;

            if(line == startpos.first)
                copied += s.substr(startpos.second);
            else if(line == endpos.first)
                copied += s.substr(0, endpos.second + 1);
            else
                copied += s;

            copied += "\n";
            line++;
        }
    }
    else
    {
        RendererLine rl;
        this->getRendererLine(startpos.first, rl);
        copied = rl.text.substr(startpos.second, endpos.second - startpos.second + 1);
    }

    return copied;
}

void ListingRenderer::setFlags(u32 flags) { m_flags = flags; }

void ListingRenderer::getRendererLine(size_t line, RendererLine& rl)
{
    ListingItem* item = m_document->itemAt(line);

    if(item->is(ListingItem::SegmentItem))
        this->renderSegment(item, rl);
    else if(item->is(ListingItem::FunctionItem))
        this->renderFunction(item, rl);
    else if(item->is(ListingItem::InstructionItem))
        this->renderInstruction(item, rl);
    else if(item->is(ListingItem::SymbolItem))
        this->renderSymbol(item, rl);
    else
        rl.push("Unknown Type: " + std::to_string(item->type));
}

void ListingRenderer::renderSegment(ListingItem *item, RendererLine &rl)
{
    m_printer->segment(m_document->segment(item->address), [&](const std::string& line) {
        rl.push(line, "segment_fg");
    });
}

void ListingRenderer::renderFunction(ListingItem *item, RendererLine& rl)
{
    if(!(m_flags & ListingRenderer::HideSegmentAndAddress))
        this->renderAddressIndent(item, rl);

    m_printer->function(m_document->symbol(item->address), [&](const std::string& pre, const std::string& sym, const std::string& post) {
        if(!pre.empty())
            rl.push(pre, "function_fg");

        rl.push(sym, "function_fg");

        if(!post.empty())
            rl.push(post, "function_fg");
    });
}

void ListingRenderer::renderInstruction(ListingItem *item, RendererLine &rl)
{
    InstructionPtr instruction = m_document->instruction(item->address);

    this->renderAddress(item, rl);
    this->renderIndent(rl);
    this->renderMnemonic(instruction, rl);
    this->renderOperands(instruction, rl);
    this->renderComments(instruction, rl);
}

void ListingRenderer::renderSymbol(ListingItem *item, RendererLine &rl)
{
    SymbolPtr symbol = m_document->symbol(item->address);

    if(symbol->is(SymbolTypes::Code)) // Label or Callback
    {
        Segment* segment = m_document->segment(symbol->address);

        if(segment->is(SegmentTypes::Bss))
        {
            this->renderAddress(item, rl);
            this->renderIndent(rl);
            rl.push(symbol->name, "label_fg");
            rl.push(" <").push("dynamic branch", "label_fg").push(">");
        }
        else
        {
            if(m_flags & ListingRenderer::HideSegmentAndAddress)
                this->renderIndent(rl, 2);
            else
                this->renderAddressIndent(item, rl);

            rl.push(symbol->name, "label_fg").push(":");
        }
    }
    else // Data
    {
        Segment* segment = m_document->segment(item->address);
        this->renderAddress(item, rl);
        this->renderIndent(rl);
        rl.push(symbol->name + " ", "label_fg");

        if(!segment->is(SegmentTypes::Bss))
        {
            if(symbol->is(SymbolTypes::Pointer))
            {
                if(symbol->isTable())
                {
                    this->renderTable(symbol, rl);
                    return;
                }
                else if(this->renderSymbolPointer(symbol, rl))
                    return;
            }

            if(symbol->is(SymbolTypes::WideStringMask))
                rl.push(REDasm::quoted(m_disassembler->readWString(symbol)), "string_fg");
            else if(symbol->is(SymbolTypes::StringMask))
                rl.push(REDasm::quoted(m_disassembler->readString(symbol)), "string_fg");
            else if(symbol->is(SymbolTypes::ImportMask))
                rl.push("<").push("import", "label_fg").push(">");
            else
            {
                u64 value = 0;
                FormatPlugin* format = m_disassembler->format();

                if(m_disassembler->readAddress(symbol->address, format->addressWidth(), &value))
                    rl.push(REDasm::hex(value, format->bits()), "data_fg");
                else
                    rl.push("??", "data_fg");
            }
        }
        else
            rl.push("??", "data_fg");
    }
}

void ListingRenderer::renderAddress(ListingItem *item, RendererLine &rl)
{
    if(m_flags & ListingRenderer::HideSegmentName && !(m_flags & ListingRenderer::HideAddress))
        rl.push(HEX_ADDRESS(item->address), "address_fg");
    else if(!(m_flags & ListingRenderer::HideAddress))
    {
        Segment* segment = m_document->segment(item->address);
        rl.push((segment ? segment->name : "unk") + ":" + HEX_ADDRESS(item->address), "address_fg");
    }
}

void ListingRenderer::renderMnemonic(const InstructionPtr &instruction, RendererLine &rl)
{
    std::string mnemonic = instruction->mnemonic + " ";

    if(instruction->isInvalid())
        rl.push(mnemonic, "instruction_invalid");
    else if(instruction->is(REDasm::InstructionTypes::Stop))
        rl.push(mnemonic, "instruction_stop");
    else if(instruction->is(REDasm::InstructionTypes::Nop))
        rl.push(mnemonic, "instruction_nop");
    else if(instruction->is(REDasm::InstructionTypes::Call))
        rl.push(mnemonic, "instruction_call");
    else if(instruction->is(REDasm::InstructionTypes::Jump))
    {
        if(instruction->is(REDasm::InstructionTypes::Conditional))
            rl.push(mnemonic, "instruction_jmp_c");
        else
            rl.push(mnemonic, "instruction_jmp");
    }
    else
        rl.push(mnemonic);
}

void ListingRenderer::renderOperands(const InstructionPtr &instruction, RendererLine &rl)
{
    m_printer->out(instruction, [&](const REDasm::Operand& operand, const std::string& opsize, const std::string& opstr) {
        if(operand.index > 0)
            rl.push(", ");

        if(!opsize.empty())
            rl.push(opsize + " ");

        if(operand.isNumeric()) {
            if(operand.is(REDasm::OperandTypes::Memory))
                rl.push(opstr, "memory_fg");
            else
                rl.push(opstr, "immediate_fg");
        }
        else if(operand.is(REDasm::OperandTypes::Displacement))
            rl.push(opstr, "displacement_fg");
        else if(operand.is(REDasm::OperandTypes::Register))
            rl.push(opstr, "register_fg");
        else
            rl.push(opstr);
    });
}

void ListingRenderer::renderComments(const InstructionPtr &instruction, RendererLine &rl)
{
    std::string s = m_document->comment(instruction->address);

    if(s.empty())
        return;

    this->renderIndent(rl, INDENT_COMMENT);
    rl.push("# " + ListingRenderer::escapeString(s), "comment_fg");
}

void ListingRenderer::renderAddressIndent(ListingItem* item, RendererLine &rl)
{
    FormatPlugin* format = m_disassembler->format();
    Segment* segment = m_document->segment(item->address);

    s64 count = format->bits() / 4;

    if(segment)
        count += segment->name.length();

    rl.push(std::string(count + INDENT_WIDTH, ' '));
}

void ListingRenderer::renderIndent(RendererLine &rl, int n) { rl.push(std::string(n * INDENT_WIDTH, ' ')); }

void ListingRenderer::renderTable(const SymbolPtr &symbol, RendererLine& rl) const
{
    u64 value = 0;
    FormatPlugin* format = m_disassembler->format();
    address_t address = symbol->address;

    rl.push("[");

    for(size_t i = 0; i < symbol->tag; i++, address += format->addressWidth())
    {
        if(i)
            rl.push(", ");

        if(!m_disassembler->readAddress(address, format->addressWidth(), &value))
        {
            rl.push("??", "data_fg");
            continue;
        }

        SymbolPtr ptrsymbol = m_document->symbol(value);

        if(!ptrsymbol)
            rl.push(REDasm::hex(value, format->bits()), "data_fg");
        else
            rl.push(ptrsymbol->name, "label_fg");
    }

    rl.push("]");
}

bool ListingRenderer::renderSymbolPointer(const SymbolPtr &symbol, RendererLine &rl) const
{
    u64 value = 0;
    FormatPlugin* format = m_disassembler->format();

   if(!m_disassembler->readAddress(symbol->address, format->addressWidth(), &value))
       return false;

   SymbolPtr ptrsymbol = m_document->symbol(value);

   if(!ptrsymbol)
       return false;

   rl.push(ptrsymbol->name, "label_fg");
   return true;
}

std::string ListingRenderer::escapeString(const std::string &s)
{
    std::string res;

    for(size_t i = 0; i < s.size(); i++)
    {
        switch(s[i])
        {
            case '\n':
                res += "\\\n";
                break;

            case '\r':
                res += "\\\r";
                break;

            case '\t':
                res += "\\\t";
                break;

            default:
                res += s[i];
                break;
        }
    }

    return res;
}

} // namespace REDasm
