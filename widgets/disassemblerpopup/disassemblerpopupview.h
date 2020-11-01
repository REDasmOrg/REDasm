#pragma once

#include <QWidget>
#include "../../renderer/surfacerenderer.h"

#define POPUP_START_COLUMNS 100
#define POPUP_START_ROWS    10
#define POPUP_MARGIN        16

class DisassemblerPopupView : public QWidget
{
    Q_OBJECT

    public:
        explicit DisassemblerPopupView(const RDContextPtr& ctx, QWidget *parent = nullptr);
        bool renderPopup(const RDSymbol* symbol);
        void moreRows();
        void lessRows();

    private:
        void renderPopup();

    protected:
        void paintEvent(QPaintEvent*) override;

    private:
        RDContextPtr m_context;
        SurfaceRenderer* m_surface;
        int m_rows{POPUP_START_ROWS}, m_maxcols{POPUP_START_COLUMNS};
};
