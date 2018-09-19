#ifndef LISTINGRENDERER_H
#define LISTINGRENDERER_H

#include "../../plugins/assembler/printer.h"
#include "listingdocument.h"

namespace REDasm {

struct RendererFormat
{
    RendererFormat(const std::string& text, const std::string& style): text(text), style(style) { }
    std::string text, style;
};

struct RendererLine
{
    RendererLine(): userdata(NULL), line(-1), index(-1), highlighted(false) { }

    void* userdata;
    int line, index;
    bool highlighted;
    std::list<RendererFormat> formats;

    std::string text() const {
        std::string s;

        for(const RendererFormat& rf : formats)
            s += rf.text;

        return s;
    }

    size_t length() const {
        size_t len = 0;

        for(const RendererFormat& rf : formats)
            len += rf.text.size();

        return len;
    }

    void push(const std::string& text, const std::string& style = std::string()) { formats.push_back(RendererFormat(text, style)); }
};

class ListingRenderer
{
    public:
        ListingRenderer(DisassemblerAPI* disassembler);
        void render(size_t start, size_t count, void* userdata = NULL);
        int getLastColumn(size_t line);
        std::string getSelectedText();

    protected:
        void getRendererLine(size_t line, RendererLine& rl);
        virtual void renderLine(const RendererLine& rl) = 0;
        void renderSegment(ListingItem* item, RendererLine& rl);
        void renderFunction(ListingItem* item, RendererLine &rl);
        void renderInstruction(ListingItem* item, RendererLine &rl);
        void renderSymbol(ListingItem* item, RendererLine &rl);
        void renderAddress(ListingItem* item, RendererLine &rl);
        void renderMnemonic(const InstructionPtr& instruction, RendererLine &rl);
        void renderOperands(const InstructionPtr& instruction, RendererLine &rl);
        void renderComments(const InstructionPtr& instruction, RendererLine &rl);
        void renderAddressIndent(ListingItem *item, RendererLine& rl);
        void renderIndent(RendererLine &rl, int n = 1);

    private:
        std::string commentString(const InstructionPtr& instruction);
        static std::string escapeString(const std::string& s);

    protected:
        ListingDocument* m_document;

    private:
        DisassemblerAPI* m_disassembler;
        PrinterPtr m_printer;
};

} // namespace REDasm

#endif // LISTINGRENDERER_H
