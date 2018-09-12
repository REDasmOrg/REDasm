#include "listingrenderer.h"
#include "../../plugins/assembler/assembler.h"
#include "../../plugins/format.h"

#define INDENT_WIDTH         2
#define INDENT_COMMENT       10
#define HEX_ADDRESS(address) REDasm::hex(address, m_disassembler->format()->bits(), false)

namespace REDasm {

ListingRenderer::ListingRenderer(DisassemblerAPI *disassembler): m_disassembler(disassembler), m_commentxpos(0)
{
    m_document = disassembler->document();
    m_printer = PrinterPtr(disassembler->assembler()->createPrinter(disassembler));
}

void ListingRenderer::render(size_t start, size_t count, void *userdata)
{
    size_t end = start + count;

    RendererFormat rf;
    rf.userdata = userdata;

    this->fontUnit(&rf.fontwidth, &rf.fontheight);

    for(size_t i = 0, line = start; line < std::min(m_document->size(), end); i++, line++)
    {
        ListingItem* item = m_document->itemAt(line);

        rf.x = 0;
        rf.y = i * rf.fontheight;

        if(item->is(ListingItem::SegmentItem))
            this->renderSegment(item, &rf);
        else if(item->is(ListingItem::FunctionItem))
            this->renderFunction(item, &rf);
        else if(item->is(ListingItem::InstructionItem))
            this->renderInstruction(item, &rf);
        else if(item->is(ListingItem::SymbolItem))
            this->renderSymbol(item, &rf);
        else
        {
            rf.text = "Unknown Type: " + std::to_string(item->type);
            this->renderText(&rf);
        }
    }
}

double ListingRenderer::measureString(const std::string &s) const
{
    double w = 0;
    this->fontUnit(&w);
    return s.size() * w;
}

void ListingRenderer::renderSegment(ListingItem *item, RendererFormat* rf)
{
    m_printer->segment(m_document->segment(item->address), [this, rf](const std::string& line) {
        rf->style = "segment_fg";
        rf->text = line;

        this->renderText(rf);
    });
}

void ListingRenderer::renderFunction(ListingItem *item, RendererFormat *rf)
{
    this->renderAddressIndent(item, rf);

    m_printer->function(m_document->symbol(item->address), [this, rf](const std::string& pre, const std::string& sym, const std::string& post) {
        rf->style = "function_fg";

        if(!pre.empty()) {
            rf->text = pre;
            this->renderText(rf);
            rf->x += this->measureString(pre);
        }

        rf->text = sym;
        this->renderText(rf);

        if(!post.empty()) { rf->x += this->measureString(sym);
            rf->text = post;
            this->renderText(rf);
        }
    });
}

void ListingRenderer::renderInstruction(ListingItem *item, RendererFormat *rf)
{
    InstructionPtr instruction = m_document->instruction(item->address);

    this->renderAddress(item, rf);
    this->renderMnemonic(instruction, rf);
    this->renderOperands(instruction, rf);

    if(rf->x > m_commentxpos)
        m_commentxpos = rf->x;

    if(!instruction->comments.empty())
        this->renderComments(instruction, rf);
}

void ListingRenderer::renderSymbol(ListingItem *item, RendererFormat *rf)
{
    SymbolPtr symbol = m_document->symbol(item->address);

    if(symbol->is(SymbolTypes::Code)) // Label
    {
        this->renderAddressIndent(item, rf);
        rf->style = "label_fg";
        rf->text = symbol->name + ":";
    }
    else
    {
        Segment* segment = m_document->segment(item->address);
        this->renderAddress(item, rf);

        rf->style = "label_fg";
        rf->text = symbol->name;
        this->renderText(rf);
        this->moveX(rf, 1);

        if(symbol->is(SymbolTypes::Data))
            rf->style = "data_fg";
        else
            rf->style = "string_fg";

        if(!segment->is(SegmentTypes::Bss))
        {
            if(symbol->is(SymbolTypes::String))
                rf->text = REDasm::quoted(m_disassembler->readString(symbol));
            else if(symbol->is(SymbolTypes::WideString))
                rf->text = REDasm::quoted(m_disassembler->readWString(symbol));
            else
            {
                u64 value = 0;
                FormatPlugin* format = m_disassembler->format();

                if(m_disassembler->readAddress(symbol->address, format->addressWidth(), &value))
                    rf->text = REDasm::hex(value, format->bits(), false);
                else
                    rf->text = "??";
            }
        }
        else
            rf->text = "??";
    }

    this->renderText(rf);
}

void ListingRenderer::renderAddress(ListingItem *item, RendererFormat *rf)
{
    Segment* segment = m_document->segment(item->address);

    rf->style = "address_fg";
    rf->text = (segment ? segment->name : "unk") + ":" + HEX_ADDRESS(item->address);

    this->renderText(rf);
    this->moveX(rf);
    this->renderIndent(rf);
}

void ListingRenderer::renderMnemonic(const InstructionPtr &instruction, RendererFormat *rf)
{
    if(instruction->isInvalid())
        rf->style = "instruction_invalid";
    else if(instruction->is(REDasm::InstructionTypes::Stop))
        rf->style = "instruction_stop";
    else if(instruction->is(REDasm::InstructionTypes::Nop))
        rf->style = "instruction_nop";
    else if(instruction->is(REDasm::InstructionTypes::Call))
        rf->style = "instruction_call";
    else if(instruction->is(REDasm::InstructionTypes::Jump))
    {
        if(instruction->is(REDasm::InstructionTypes::Conditional))
            rf->style = "instruction_jmp_c";
        else
            rf->style = "instruction_jmp";
    }

    rf->text = instruction->mnemonic + " ";
    this->renderText(rf);
    this->moveX(rf);
}

void ListingRenderer::renderOperands(const InstructionPtr &instruction, RendererFormat *rf)
{
    m_printer->out(instruction, [this, instruction, rf](const REDasm::Operand& operand, const std::string& opsize, const std::string& opstr) {
        rf->text.clear();

        if(operand.index > 0) {
            rf->style.clear();
            rf->text = ", ";
            this->renderText(rf);
            rf->x += rf->fontwidth * 2;
            rf->text.clear();
        }

        if(operand.isNumeric()) {
            if(operand.is(REDasm::OperandTypes::Memory))
                rf->style = "memory_fg";
            else
                rf->style = "immediate_fg";
        }
        else if(operand.is(REDasm::OperandTypes::Displacement))
            rf->style = "displacement_fg";
        else if(operand.is(REDasm::OperandTypes::Register))
            rf->style = "register_fg";

        if(!opsize.empty())
            rf->text = opsize + " ";

        rf->text += opstr;
        this->renderText(rf);
        this->moveX(rf);
    });
}

void ListingRenderer::renderComments(const InstructionPtr &instruction, RendererFormat *rf)
{
    rf->x = m_commentxpos + (INDENT_WIDTH * rf->fontwidth);
    rf->style = "comment_fg";
    rf->text = ListingRenderer::commentString(instruction);
    this->renderText(rf);
}

void ListingRenderer::renderAddressIndent(ListingItem* item, RendererFormat *rf)
{
    FormatPlugin* format = m_disassembler->format();
    Segment* segment = m_document->segment(item->address);

    int count = format->bits() / 4;

    if(segment)
        count += segment->name.length();

    rf->style.clear();
    rf->text = std::string(count + INDENT_WIDTH, ' ');

    this->renderText(rf);
    this->moveX(rf);
}

void ListingRenderer::renderIndent(RendererFormat* rf, int n)
{
    rf->style.clear();
    rf->text = std::string(n * INDENT_WIDTH, ' ');

    this->renderText(rf);
    this->moveX(rf);
}

void ListingRenderer::moveX(RendererFormat *rf, size_t extra) const { rf->x += this->measureString(rf->text) + (rf->fontwidth * extra); }

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

    return ListingRenderer::escapeString(ss.str());
}

} // namespace REDasm
