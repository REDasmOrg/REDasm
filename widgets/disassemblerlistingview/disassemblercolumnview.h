#pragma once

#include <redasm/disassembler/disassembler.h>
#include <QWidget>
#include <QList>
#include <QPair>
#include <QSet>

class DisassemblerColumnView : public QWidget
{
    Q_OBJECT

    private:
        struct ArrowPath{ size_t startidx, endidx; QColor color; };

    public:
        explicit DisassemblerColumnView(QWidget *parent = nullptr);
        void setDisassembler(const REDasm::DisassemblerPtr &disassembler);
        void renderArrows(size_t start, size_t count);

    protected:
        virtual void paintEvent(QPaintEvent*);

    private:
        bool isPathSelected(const ArrowPath& path) const;
        void fillArrow(QPainter* painter, int y, const QFontMetrics &fm);
        void insertPath(const REDasm::ListingItem& fromitem, size_t fromidx, size_t toidx);

    private:
        REDasm::DisassemblerPtr m_disassembler;
        QList<ArrowPath> m_paths;
        QSet<QPair<size_t, size_t>> m_done;
        size_t m_first{REDasm::npos}, m_last{REDasm::npos};
};
