#ifndef LISTINGMAP_H
#define LISTINGMAP_H

#include <QWidget>
#include <redasm/disassembler/disassemblerapi.h>

class ListingMap : public QWidget
{
    Q_OBJECT

    public:
        explicit ListingMap(QWidget *parent = 0);
        void setDisassembler(const REDasm::DisassemblerPtr &disassembler);
        QSize sizeHint() const override;

    private:
        int calculateSize(u64 sz) const;
        int calculatePosition(offset_t offset) const;
        int itemSize() const;
        QRect buildRect(int offset, int itemsize) const;
        bool checkOrientation();
        void drawLabels(QPainter *painter);
        void renderSegments(QPainter *painter);
        void renderFunctions(QPainter *painter);
        void renderSeek(QPainter *painter);

    protected:
        void paintEvent(QPaintEvent*) override;
        void resizeEvent(QResizeEvent* e) override;

    private:
        REDasm::DisassemblerPtr m_disassembler;
        s32 m_orientation, m_totalsize;
        u64 m_lastseek;
};

#endif // LISTINGMAP_H
