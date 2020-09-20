#include "listingmap.h"
#include "../../../themeprovider.h"
#include <rdapi/graph/functiongraph.h>
#include <QApplication>
#include <QPainter>
#include <algorithm>
#include <cmath>

#define LISTINGMAP_SIZE 64

ListingMap::ListingMap(QWidget *parent) : QWidget(parent) { }

ListingMap::~ListingMap()
{
    if(m_disassembler) RDDisassembler_Unsubscribe(m_disassembler.get(), this);
    if(m_renderer) m_renderer->abort();
}

void ListingMap::linkTo(IDisassemblerCommand* command)
{
    m_command = command;
    m_disassembler = command->disassembler();
    m_document = RDDisassembler_GetDocument(m_disassembler.get());

    RDDisassembler_Subscribe(m_disassembler.get(), this, [](const RDEventArgs* e) {
        auto* thethis = reinterpret_cast<ListingMap*>(e->owner);
        if(RDDisassembler_IsBusy(thethis->m_disassembler.get()) || !thethis->m_document) return;

        switch(e->eventid) {
            case Event_CursorPositionChanged: thethis->m_renderer->renderMap(); break;
            case Event_BusyChanged: thethis->m_renderer->renderMap(); break;
            default: break;
        }
    }, nullptr);

    if(m_renderer) m_renderer->deleteLater();
    m_renderer = new ListingMapRenderer(command, this);
    connect(m_renderer, &ListingMapRenderer::renderCompleted, this, &ListingMap::onRenderCompleted);
    m_renderer->renderMap();
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
