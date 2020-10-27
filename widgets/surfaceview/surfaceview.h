#pragma once

#include <QWidget>
#include "../hooks/icommand.h"

class SurfaceRenderer;

class SurfaceView : public QWidget
{
    Q_OBJECT

    public:
        explicit SurfaceView(const RDContextPtr& ctx, QWidget *parent = nullptr);

    protected:
        void resizeEvent(QResizeEvent *event) override;
        void paintEvent(QPaintEvent*event) override;
        void mousePressEvent(QMouseEvent* event) override;
        void mouseMoveEvent(QMouseEvent* event) override;
        void mouseDoubleClickEvent(QMouseEvent* e) override;
        void wheelEvent(QWheelEvent *event) override;
        void keyPressEvent(QKeyEvent *e) override;

    private:
        RDContextPtr m_context;
        SurfaceRenderer* m_renderer;
};

