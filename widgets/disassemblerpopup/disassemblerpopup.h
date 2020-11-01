#pragma once

#include <QWidget>
#include <rdapi/rdapi.h>
#include "disassemblerpopupview.h"

class DisassemblerPopup : public QWidget
{
    public:
        explicit DisassemblerPopup(const RDContextPtr& ctx, QWidget* parent = nullptr);
        void popup(const RDSymbol* symbol);

    protected:
        void mouseMoveEvent(QMouseEvent *event) override;
        void wheelEvent(QWheelEvent* event) override;

    private:
        DisassemblerPopupView* m_popupview;
        RDContextPtr m_context;
        QPointF m_lastpos;
};
