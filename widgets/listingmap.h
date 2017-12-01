#ifndef LISTINGMAP_H
#define LISTINGMAP_H

#include <QWidget>
#include <QMap>
#include <QColor>
#include "../redasm/disassembler/disassembler.h"

class ListingMap : public QWidget
{
    Q_OBJECT

    private:
        struct Item {
            u64 address, offset, size;
            QColor color;
        };

    public:
        explicit ListingMap(QWidget *parent = 0);
        void render(REDasm::Disassembler *disassembler);

    private:
        const Item *segmentBase(REDasm::Disassembler* disassembler, REDasm::SymbolPtr symbol) const;

    protected:
        virtual void paintEvent(QPaintEvent *);

    private:
        u64 _size;
        QMap<u64, Item> _segments;
        QMap<u64, Item> _functions;
};

#endif // LISTINGMAP_H
