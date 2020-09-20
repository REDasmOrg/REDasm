#pragma once

#include <rdapi/rdapi.h>
#include <QWidget>
#include <QList>
#include <QPair>
#include <QSet>
#include "../hooks/idisassemblercommand.h"

class DisassemblerTextView;

class DisassemblerColumnView : public QWidget
{
    Q_OBJECT

    private:
        struct ArrowPath{ size_t startidx, endidx; QColor color; };

    public:
        explicit DisassemblerColumnView(QWidget *parent = nullptr);
        virtual ~DisassemblerColumnView();
        void linkTo(DisassemblerTextView* textview);

    protected:
        void paintEvent(QPaintEvent*) override;

    private:
        bool isPathSelected(const ArrowPath& path) const;
        void fillArrow(QPainter* painter, int y, const QFontMetrics &fm);
        void insertPath(const RDNet* net, const RDDocumentItem& fromitem, size_t fromidx, size_t toidx);
        void renderArrows(size_t start, size_t count);

    private slots:
        void renderArrows();

    private:
        DisassemblerTextView* m_textview{nullptr};
        RDDisassemblerPtr m_disassembler;
        RDDocument* m_document{nullptr};
        QList<ArrowPath> m_paths;
        QSet<QPair<size_t, size_t>> m_done;
        size_t m_first{RD_NPOS}, m_last{RD_NPOS};
};
