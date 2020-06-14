#pragma once

#include "qtrenderer.h"
#include <QTextDocument>

class DocumentRenderer : public QtRenderer
{
    public:
        DocumentRenderer(QTextDocument* textdocument, RDDisassembler* disassembler, RDCursor* cursor, rd_flag flags = RendererFlags_Normal);
        QTextDocument* textDocument() const;
        qreal maxWidth() const;
        void render(size_t first, size_t last);

    private:
        void render(const RDRendererItem* ritem, size_t index);

    private:
        QTextDocument* m_textdocument;
        qreal m_maxwidth{0};
};

