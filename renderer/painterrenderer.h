#pragma once

#include <rdapi/rdapi.h>
#include <rdapi/renderer.h>
#include <QFontMetrics>
#include <QPointF>

class QPainter;

class PainterRenderer
{
    public:
        PainterRenderer(RDDisassembler* disassembler, flag_t flags = RendererFlags_Normal);
        ~PainterRenderer();
        QString currentWord() const;
        QString selectedText() const;
        bool selectedSymbol(RDSymbol* symbol) const;
        const QFontMetricsF fontMetrics() const;
        const RDRenderer* handle() const;
        RDCursor* cursor() const;
        RDCursorPos hitTest(const QPointF& p);
        void moveTo(const QPointF& p);
        void select(const QPointF& p);
        void render(QPainter* painter, size_t first, size_t last);

    private:
        void render(const RDRendererItem* item, size_t index);

    private:
        RDDocument* m_document;
        RDRenderer* m_renderer;
        RDCursor* m_cursor;
        QPainter* m_painter{nullptr};
        QFontMetricsF m_fontmetrics;
};
