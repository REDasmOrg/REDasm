#include "listingmap.h"
#include "../../../themeprovider.h"
#include <rdapi/graph/functiongraph.h>
#include <QApplication>
#include <QPainter>
#include <algorithm>
#include <cmath>

#define LISTINGMAP_SIZE 64

ListingMap::ListingMap(const RDContextPtr& ctx, QWidget *parent) : QWidget(parent), m_context(ctx)
{
    m_renderer = new ListingMapRenderer(ctx, this);

    RDObject_Subscribe(m_context.get(), this, [](const RDEventArgs* e) {
        auto* thethis = reinterpret_cast<ListingMap*>(e->owner);
        if(RDContext_IsBusy(thethis->m_context.get())) return;

        switch(e->id) {
            case Event_CursorPositionChanged: thethis->m_renderer->renderMap(); break;
            case Event_BusyChanged: thethis->m_renderer->renderMap(); break;
            default: break;
        }
    }, nullptr);

    connect(m_renderer, &ListingMapRenderer::renderCompleted, this, &ListingMap::onRenderCompleted);
    m_renderer->renderMap();
}

ListingMap::~ListingMap()
{
    RDObject_Unsubscribe(m_context.get(), this);
    if(m_renderer) m_renderer->abort();
}

QSize ListingMap::sizeHint() const { return { LISTINGMAP_SIZE, LISTINGMAP_SIZE }; }

void ListingMap::onRenderCompleted(const QImage& image)
{
    m_pixmap = QPixmap::fromImage(image);
    this->update();
}

void ListingMap::paintEvent(QPaintEvent *)
{
   if(!m_command) return;
   QPainter painter(this);
   painter.drawPixmap(0, 0, m_pixmap);
}

void ListingMap::resizeEvent(QResizeEvent *e)
{
    QWidget::resizeEvent(e);
    if(m_renderer) m_renderer->renderMap();
}
