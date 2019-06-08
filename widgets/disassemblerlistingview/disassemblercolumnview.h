#ifndef DISASSEMBLERCOLUMNVIEW_H
#define DISASSEMBLERCOLUMNVIEW_H

#include <QWidget>
#include <QList>
#include <QPair>
#include <QSet>
#include <redasm/disassembler/disassembler.h>
#include <redasm/disassembler/listing/listingdocument.h>

class DisassemblerColumnView : public QWidget
{
    Q_OBJECT

    private:
        struct ArrowPath{ u64 startidx, endidx; QColor color; };

    public:
        explicit DisassemblerColumnView(QWidget *parent = nullptr);
        void setDisassembler(const REDasm::DisassemblerPtr &disassembler);
        void renderArrows(size_t start, size_t count);

    protected:
        virtual void paintEvent(QPaintEvent*);

    private:
        bool isPathSelected(const ArrowPath& path) const;
        void fillArrow(QPainter* painter, int y, const QFontMetrics &fm);
        void insertPath(REDasm::ListingItem *fromitem, u64 fromidx, u64 toidx);

    private:
        REDasm::DisassemblerPtr m_disassembler;
        QList<ArrowPath> m_paths;
        QSet< QPair<u64, u64> > m_done;
        u64 m_first, m_last;
};

#endif // DISASSEMBLERCOLUMNVIEW_H
