#ifndef DISASSEMBLERCOLUMNVIEW_H
#define DISASSEMBLERCOLUMNVIEW_H

#include <QWidget>
#include <QList>
#include <QPair>
#include <QSet>
#include <redasm/disassembler/disassemblerapi.h>
#include <redasm/disassembler/listing/listingdocument.h>

class DisassemblerColumnView : public QWidget
{
    Q_OBJECT

    private:
        typedef QPair<int, int> ArrowPath;

    public:
        explicit DisassemblerColumnView(QWidget *parent = nullptr);
        void setDisassembler(REDasm::DisassemblerAPI* disassembler);
        void renderArrows(int start, int count);

    protected:
        virtual void paintEvent(QPaintEvent*);

    private:
        bool isPathSelected(const ArrowPath& path) const;
        void fillArrow(QPainter* painter, int y, const QFontMetrics &fm);
        bool applyStyle(const REDasm::InstructionPtr& instruction, int idx);
        bool applyStyle(int idx);

    private:
        REDasm::DisassemblerAPI* m_disassembler;
        REDasm::ListingDocument m_document;
        QSet<ArrowPath> m_paths;
        QHash<int, QColor> m_pathstyle;
        int m_first, m_last;
};

#endif // DISASSEMBLERCOLUMNVIEW_H
