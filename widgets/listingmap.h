#ifndef LISTINGMAP_H
#define LISTINGMAP_H

#include <QWidget>
#include <QList>
#include <redasm/disassembler/listing/listingdocument.h>
#include <redasm/disassembler/disassemblerapi.h>

class ListingMap : public QWidget
{
    Q_OBJECT

    public:
        explicit ListingMap(QWidget *parent = 0);
        void setDisassembler(const REDasm::DisassemblerPtr &disassembler);
        virtual QSize sizeHint() const;

    private:
        int calculateSize(u64 sz) const;
        int calculatePosition(offset_t offset) const;
        int itemSize() const;
        QRect buildRect(int offset, int itemsize) const;
        bool checkOrientation();
        void onDocumentChanged(const REDasm::ListingDocumentChanged* ldc);
        void addItem(const REDasm::ListingItem* item);
        void removeItem(const REDasm::ListingItem* item);
        void drawLabels(QPainter *painter);
        void renderSegments(QPainter *painter);
        void renderFunctions(QPainter *painter);
        void renderSeek(QPainter *painter);

    protected:
        virtual void paintEvent(QPaintEvent*);
        virtual void resizeEvent(QResizeEvent* e);

    private:
        REDasm::DisassemblerPtr m_disassembler;
        QList<const REDasm::ListingItem*> m_functions;
        s32 m_orientation, m_totalsize;
        u64 m_lastseek;
};

#endif // LISTINGMAP_H
