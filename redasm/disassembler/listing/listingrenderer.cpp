#include "listingrenderer.h"
#include "../../plugins/assembler/assembler.h"
#include "../../plugins/format.h"

#define INDENT_WIDTH         2
#define INDENT_COMMENT       10
#define HEX_ADDRESS(address) REDasm::hex(address, m_disassembler->format()->bits(), false)

namespace REDasm {

ListingRenderer::ListingRenderer(DisassemblerAPI *disassembler): m_disassembler(disassembler), m_commentcolumn(0)
{
    m_document = disassembler->document();
    m_printer = PrinterPtr(disassembler->assembler()->createPrinter(disassembler));
}

void ListingRenderer::render(size_t start, size_t count, void *userdata)
{
    ListingCursor* cur = m_document->cursor();
    size_t end = start + count;

    for(size_t i = 0, line = start; line < std::min(m_document->size(), end); i++, line++)
    {
        ListingItem* item = m_document->itemAt(line);

        RendererLine rl;
        rl.userdata = userdata;
        rl.index = i;
        rl.highlighted = cur->currentLine() == static_cast<int>(line);

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

        this->renderLine(rl);
    }
}

void ListingRenderer::renderSegment(ListingItem *item, RendererLine &rl)
{
    m_printer->segment(m_document->segment(item->address), [&](const std::string& line) {
        rl.push(line, "segment_fg");
    });
}

void ListingRenderer::renderFunction(ListingItem *item, RendererLine& rl)
{
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
    this->renderMnemonic(instruction, rl);
    this->renderOperands(instruction, rl);

    m_commentcolumn = std::max(rl.length(), m_commentcolumn);

    if(!instruction->comments.empty())
        this->renderComments(instruction, rl);
}

void ListingRenderer::renderSymbol(ListingItem *item, RendererLine &rl)
{
    SymbolPtr symbol = m_document->symbol(item->address);

    if(symbol->is(SymbolTypes::Code)) // Label
    {
        this->renderAddressIndent(item, rl);
        rl.push(symbol->name + ":", "label_fg");
    }
    else
    {
        Segment* segment = m_document->segment(item->address);
        this->renderAddress(item, rl);
        rl.push(symbol->name + " ", "label_fg");

        if(!segment->is(SegmentTypes::Bss))
        {
            if(symbol->is(SymbolTypes::String))
                rl.push(REDasm::quoted(m_disassembler->readString(symbol)), "string_fg");
            else if(symbol->is(SymbolTypes::WideString))
                rl.push(REDasm::quoted(m_disassembler->readWString(symbol)), "string_fg");
            else
            {
                u64 value = 0;
                FormatPlugin* format = m_disassembler->format();

                if(m_disassembler->readAddress(symbol->address, format->addressWidth(), &value))
                    rl.push(REDasm::hex(value, format->bits(), false), "data_fg");
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
    Segment* segment = m_document->segment(item->address);
    rl.push((segment ? segment->name : "unk") + ":" + HEX_ADDRESS(item->address), "address_fg");
    this->renderIndent(rl);
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

void ListingRenderer::renderComments(const InstructionPtr &instruction, RendererLine &rl) { rl.push("comment_fg", this->commentString(instruction)); }

void ListingRenderer::renderAddressIndent(ListingItem* item, RendererLine &rl)
{
    FormatPlugin* format = m_disassembler->format();
    Segment* segment = m_document->segment(item->address);

    int count = format->bits() / 4;

    if(segment)
        count += segment->name.length();

    rl.push(std::string(count + INDENT_WIDTH, ' '));
}

void ListingRenderer::renderIndent(RendererLine &rl, int n) { rl.push(std::string(n * INDENT_WIDTH, ' ')); }

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

            default:
                res += s[i];
                break;
        }
    }

    return res;
}

std::string ListingRenderer::commentString(const InstructionPtr &instruction)
{
    std::stringstream ss;
    ss << "# ";

    for(const std::string& s : instruction->comments)
    {
        if(s != instruction->comments.front())
            ss << " | ";

        ss << s;
    }

    return std::string(m_commentcolumn, ' ') + ListingRenderer::escapeString(ss.str());
}

} // namespace REDasm
