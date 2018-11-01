#ifndef DISASSEMBLERCOLUMNVIEW_H
#define DISASSEMBLERCOLUMNVIEW_H

#include <QWidget>
#include <QList>
#include <QPair>
#include <QSet>
#include "../../redasm/disassembler/disassemblerapi.h"
#include "../../redasm/disassembler/listing/listingdocument.h"

class DisassemblerColumnView : public QWidget
{
    Q_OBJECT

    public:
        explicit DisassemblerColumnView(QWidget *parent = nullptr);
        void setDisassembler(REDasm::DisassemblerAPI* disassembler);
        void renderArrows(int start, int count);

    protected:
        virtual void paintEvent(QPaintEvent*);

    private:
        void fillArrow(QPainter* painter, int y, const QFontMetrics &fm);

    private:
        REDasm::DisassemblerAPI* m_disassembler;
        REDasm::ListingDocument* m_document;
        QList< QPair<int, int> > m_paths;
        QHash<int, QColor> m_pathstyle;
        int m_first, m_last;
};

#endif // DISASSEMBLERCOLUMNVIEW_H
