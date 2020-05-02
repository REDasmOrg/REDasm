#pragma once

#include <rdapi/rdapi.h>
#include <rdapi/renderer.h>
#include <QFontMetricsF>
#include <QPointF>
#include <QString>

class QtRenderer
{
    public:
        QtRenderer(RDDisassembler* disassembler, RDCursor* cursor = nullptr, flag_t flags = RendererFlags_Normal);
        ~QtRenderer();
        const QFontMetricsF& fontMetrics() const;
        const RDRenderer* handle() const;
        RDCursor* cursor() const;
        RDCursorPos hitTest(const QPointF& p);
        QString currentWord() const;
        QString selectedText() const;
        QString getWordFromPoint(const QPointF& pt, RDCursorRange* range);
        bool selectedSymbol(RDSymbol* symbol) const;
        void selectWordFromPoint(const QPointF& pt);
        void setStartOffset(size_t offset);
        void moveTo(const QPointF& p);
        void select(const QPointF& p);
        void copy() const;

    protected:
        QFontMetricsF m_fontmetrics;
        RDDocument* m_document;
        RDRenderer* m_renderer;
        RDCursor* m_cursor;
        size_t m_offset{0};
        bool m_ownscursor{true};
};

