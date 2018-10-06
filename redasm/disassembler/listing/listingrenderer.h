#ifndef LISTINGRENDERER_H
#define LISTINGRENDERER_H

#include "../../plugins/assembler/printer.h"
#include "listingdocument.h"

namespace REDasm {

struct RendererFormat
{
    RendererFormat(int start, int length, const std::string& style): start(start), length(length), style(style) { }
    int start, length;
    std::string style;
};

struct RendererLine
{
    RendererLine(): userdata(NULL), line(-1), index(-1), highlighted(false) { }

    void* userdata;
    int line, index;
    bool highlighted;
    std::list<RendererFormat> formats;
    std::string text;

    size_t length() const { return text.length(); }

    void push(const std::string& text, const std::string& style = std::string()) {
        formats.push_back(RendererFormat(this->text.size(), text.length(), style));
        this->text += text;
    }
};

class ListingRenderer
{
    protected:
        enum: u32 { Normal = 0, HideSegmentName = 1 };

    public:
        ListingRenderer(DisassemblerAPI* disassembler);
        void render(size_t start, size_t count, void* userdata = NULL);
        int getLastColumn(size_t line);
        std::string getLine(size_t line);
        std::string getSelectedText();

    protected:
        virtual void renderLine(const RendererLine& rl) = 0;
        void setFlags(u32 flags);
        void getRendererLine(size_t line, RendererLine& rl);
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
        u32 m_flags;
        DisassemblerAPI* m_disassembler;
        PrinterPtr m_printer;
};

} // namespace REDasm

#endif // LISTINGRENDERER_H
