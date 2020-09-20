#pragma once

#include <rdapi/rdapi.h>
#include <rdapi/renderer.h>
#include "../hooks/idisassemblercommand.h"
#include <QFontMetricsF>
#include <QPointF>
#include <QString>

class QtRenderer: public QObject
{
    Q_OBJECT

    public:
        QtRenderer(const RDDisassemblerPtr& disassembler, RDCursor* cursor = nullptr, rd_flag flags = RendererFlags_Normal, QObject* parent = 0);
        virtual ~QtRenderer();
        const QFontMetricsF& fontMetrics() const;
        const RDRenderer* handle() const;
        RDCursor* cursor() const;
        RDCursorPos hitTest(const QPointF& p, bool screen = false);
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
        RDDisassemblerPtr m_disassembler;
        RDDocument* m_document;
        RDRenderer* m_renderer;
        RDCursor* m_cursor;
        size_t m_offset{0};
        bool m_ownscursor{true};
};

