#include "cursorscrollarea.h"
#include <QMouseEvent>

CursorScrollArea::CursorScrollArea(QWidget *parent) : QAbstractScrollArea(parent) { }

void CursorScrollArea::onCursorBlink()
{

}

void CursorScrollArea::mousePressEvent(QMouseEvent* e)
{
    //if(m_cursor && (e->button() == Qt::BackButton)) RDCursor_GoBack(m_cursor);
    //else if(m_cursor && (e->button() == Qt::ForwardButton)) RDCursor_GoForward(m_cursor);
    QAbstractScrollArea::mousePressEvent(e);
}

bool CursorScrollArea::event(QEvent* e)
{
    //if(m_cursor && (e->type() == QEvent::FocusIn)) this->blinkCursor();
    //else if(m_cursor && (e->type() == QEvent::FocusOut)) this->stopBlinkCursor();
    return QAbstractScrollArea::event(e);
}
