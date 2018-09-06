#ifndef LISTINGRENDERER_H
#define LISTINGRENDERER_H

#include "../../plugins/assembler/printer.h"
#include "listingdocument.h"

namespace REDasm {

struct RendererFormat
{
    double fontwidth, fontheight, x, y;
    std::string text, style;
    void* userdata;
};

class ListingRenderer
{
    public:
        ListingRenderer(DisassemblerAPI* disassembler);
        void render(size_t start, size_t count, void* userdata = NULL);

    public:
        virtual void renderText(const RendererFormat* rf) = 0;

    protected:
        virtual void fontUnit(double* w = NULL, double* h = NULL) const = 0;

    protected:
        double measureString(const std::string& s) const;
        void renderSegment(ListingItem* item, RendererFormat *rf);
        void renderFunction(ListingItem* item, RendererFormat* rf);
        void renderInstruction(ListingItem* item, RendererFormat* rf);
        void renderAddress(ListingItem* item, RendererFormat* rf);
        void renderMnemonic(const InstructionPtr& instruction, RendererFormat* rf);
        void renderOperands(const InstructionPtr& instruction, RendererFormat* rf);
        void renderComments(const InstructionPtr& instruction, RendererFormat* rf);
        void renderAddressIndent(ListingItem *item, RendererFormat* rf);
        void renderIndent(RendererFormat *rf, int n = 1);

    private:
        static std::string commentString(const InstructionPtr& instruction);

    private:
        DisassemblerAPI* m_disassembler;
        ListingDocument* m_document;
        PrinterPtr m_printer;
        double m_commentcolumn;

};

} // namespace REDasm

#endif // LISTINGRENDERER_H
