#ifndef LISTINGMAP_H
#define LISTINGMAP_H

#include <QWidget>
#include <redasm/disassembler/disassembler.h>

class ListingMap : public QWidget
{
    Q_OBJECT

    public:
        explicit ListingMap(QWidget *parent = 0);
        void setDisassembler(REDasm::DisassemblerAPI* disassembler);

    private:
        int calculateWidth(u64 sz) const;
        void onDocumentChanged(const REDasm::ListingDocumentChanged* ldc);
        void addItem(const REDasm::ListingItem* item);
        void removeItem(const REDasm::ListingItem* item);

    protected:
        virtual void paintEvent(QPaintEvent *);

    private:
        REDasm::DisassemblerAPI* m_disassembler;
        QList<const REDasm::ListingItem*> m_segments;
        QVector<const REDasm::ListingItem*> m_functions;
        s32 m_totalsize;
};

#endif // LISTINGMAP_H
