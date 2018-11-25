#ifndef LISTINGRENDERER_H
#define LISTINGRENDERER_H

#include "../../plugins/assembler/printer.h"
#include "listingdocument.h"

namespace REDasm {

struct RendererFormat
{
    RendererFormat(s64 start, s64 length, const std::string& style): start(start), length(length), style(style) { }
    s64 start, length;
    std::string style;
};

struct RendererLine
{
    RendererLine(): userdata(NULL), line(0), index(0), highlighted(false) { }

    void* userdata;
    u64 line, index;
    bool highlighted;
    std::list<RendererFormat> formats;
    std::string text;

    size_t length() const { return text.length(); }

    RendererLine& push(const std::string& text, const std::string& style = std::string()) {
        formats.push_back(RendererFormat(this->text.size(), text.length(), style));
        this->text += text;
        return *this;
    }
};

class ListingRenderer
{
    protected:
        enum: u32 { Normal = 0, HideSegmentName = 1, HideAddress = 2,
                    HideSegmentAndAddress = HideSegmentName | HideAddress
                  };

    public:
        ListingRenderer(DisassemblerAPI* disassembler);
        virtual void render(u64 start, u64 count, void* userdata = NULL);
        u64 getLastColumn(u64 line);
        std::string getLine(u64 line);
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
        void renderTable(const SymbolPtr &symbol, RendererLine &rl) const;
        bool renderSymbolPointer(const SymbolPtr& symbol, RendererLine& rl) const;
        static std::string escapeString(const std::string& s);

    protected:
        ListingDocument* m_document;
        ListingCursor* m_cursor;

    private:
        u32 m_flags;
        DisassemblerAPI* m_disassembler;
        PrinterPtr m_printer;
};

} // namespace REDasm

#endif // LISTINGRENDERER_H
