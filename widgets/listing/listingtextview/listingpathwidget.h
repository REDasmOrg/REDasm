#pragma once

#include <rdapi/rdapi.h>
#include <QWidget>
#include <QList>
#include <QPair>
#include <QSet>
#include "../../../hooks/isurface.h"

class ListingTextWidget;

class ListingPathWidget : public QWidget
{
    Q_OBJECT

    private:
        struct ArrowPath{ size_t startidx, endidx; QColor color; };

    public:
        explicit ListingPathWidget(QWidget *parent = nullptr);
        virtual ~ListingPathWidget();
        void linkTo(ListingTextWidget* textview);

    protected:
        void paintEvent(QPaintEvent*) override;

    private:
        bool isPathSelected(const RDPathItem* item) const;
        void fillArrow(QPainter* painter, int y, const QFontMetrics &fm);

    private:
        ListingTextWidget* m_textview{nullptr};
        RDContextPtr m_context;
        RDDocument* m_document{nullptr};
        QList<ArrowPath> m_paths;
        QSet<QPair<size_t, size_t>> m_done;
        size_t m_first{RD_NVAL}, m_last{RD_NVAL};
};
