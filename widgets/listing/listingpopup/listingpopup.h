#pragma once

#include <QWidget>
#include <rdapi/rdapi.h>
#include "listingpopupview.h"

class ListingPopup : public QWidget
{
    public:
        explicit ListingPopup(const RDContextPtr& ctx, QWidget* parent = nullptr);
        void popup(const RDSymbol* symbol);

    protected:
        void mouseMoveEvent(QMouseEvent *event) override;
        void wheelEvent(QWheelEvent* event) override;

    private:
        ListingPopupView* m_popupview;
        RDContextPtr m_context;
        QPointF m_lastpos;
};
