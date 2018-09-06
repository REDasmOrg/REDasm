#ifndef DISASSEMBLERTEXTDOCUMENT_H
#define DISASSEMBLERTEXTDOCUMENT_H

#include <QFont>
#include <QFontMetrics>
#include "../disassemblerview/disassemblerdocument.h"
#include "../../redasm/disassembler/listing/listingrenderer.h"

class DisassemblerTextDocument : public REDasm::ListingRenderer
{
    public:
        DisassemblerTextDocument(const QFont& font, REDasm::DisassemblerAPI* disassembler);
        virtual void renderText(const REDasm::RendererFormat* rf);

    protected:
        virtual void fontUnit(double* w = NULL, double* h = NULL) const;

    private:
        QFontMetrics m_fontmetrics;
};

#endif // DISASSEMBLERTEXTDOCUMENT_H
