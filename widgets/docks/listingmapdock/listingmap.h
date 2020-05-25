#pragma once

#include <QWidget>
#include "../../../hooks/idisassemblercommand.h"
#include <rdapi/rdapi.h>

class ListingMap : public QWidget
{
    Q_OBJECT

    public:
        explicit ListingMap(QWidget *parent = 0);
        virtual ~ListingMap();
        void linkTo(IDisassemblerCommand* command);
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
        IDisassemblerCommand* m_command{nullptr};
        RDDocument* m_document{nullptr};
        s32 m_orientation{Qt::Vertical};
        size_t m_totalsize{0};
};
