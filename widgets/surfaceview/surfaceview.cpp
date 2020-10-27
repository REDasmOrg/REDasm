#include "surfaceview.h"
#include <QFontDatabase>
#include <QWheelEvent>
#include <QPainter>
#include <cmath>
#include "../renderer/surfacerenderer.h"
#include "../themeprovider.h"
#include "../redasmsettings.h"

#define DOCUMENT_WHEEL_LINES  3

SurfaceView::SurfaceView(const RDContextPtr& ctx, QWidget *parent) : QWidget(parent), m_context(ctx)
{
    this->setFont(REDasmSettings::font());
    this->setFocusPolicy(Qt::StrongFocus);

    m_renderer = new SurfaceRenderer(ctx, this);
    connect(m_renderer, &SurfaceRenderer::renderCompleted, this, [&]() { this->update(); });
}

void SurfaceView::resizeEvent(QResizeEvent* event)
{
    QWidget::resizeEvent(event);
    if(m_renderer) m_renderer->resize();
}

void SurfaceView::paintEvent(QPaintEvent* event)
{
    if(!m_renderer)
    {
        QWidget::paintEvent(event);
        return;
    }

    QPainter painter(this);
    painter.drawPixmap(QPoint(0, 0), m_renderer->pixmap());
}

void SurfaceView::mousePressEvent(QMouseEvent* event)
{
    if(event->button() == Qt::LeftButton)
    {
        m_renderer->moveTo(event->pos());
        event->accept();
        return;
    }

    QWidget::mousePressEvent(event);
}

void SurfaceView::mouseMoveEvent(QMouseEvent* event)
{
    if(event->buttons() == Qt::LeftButton)
    {
        m_renderer->select(event->pos());
        event->accept();
        return;
    }

    QWidget::mouseMoveEvent(event);
}

void SurfaceView::mouseDoubleClickEvent(QMouseEvent* e)
{
    QWidget::mouseDoubleClickEvent(e);
}

void SurfaceView::wheelEvent(QWheelEvent* event)
{
    QPoint ndegrees = event->angleDelta() / 8;
    QPoint nsteps = ndegrees / 15;
    m_renderer->scroll(-nsteps.y() * DOCUMENT_WHEEL_LINES, nsteps.x());
    event->accept();
}

void SurfaceView::keyPressEvent(QKeyEvent* e)
{
    QWidget::keyPressEvent(e);
}
