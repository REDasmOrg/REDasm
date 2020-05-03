#include "cursorscrollarea.h"
#include "../renderer/qtrenderer.h"
#include <QApplication>
#include <QTimerEvent>
#include <QMouseEvent>
#include <QStyleHints>

CursorScrollArea::CursorScrollArea(QWidget *parent) : QAbstractScrollArea(parent) { }
void CursorScrollArea::setBlinkCursor(RDCursor* cursor) { m_cursor = cursor; }

CursorScrollArea::~CursorScrollArea()
{
    if(!m_blinktimer) return;

    this->killTimer(m_blinktimer);
    m_blinktimer = 0;
}

void CursorScrollArea::onCursorBlink() { }

void CursorScrollArea::stopTimer()
{
    if(m_blinktimer)
    {
        this->killTimer(m_blinktimer);
        m_blinktimer = 0;
    }
}

void CursorScrollArea::stopBlinkCursor()
{
    this->stopTimer();
    if(m_cursor) RDCursor_Disable(m_cursor);
}

void CursorScrollArea::blinkCursor()
{
    this->stopTimer();

    if(!m_cursor || !this->isVisible()) return;

    if(this->hasFocus())
    {
        int flashtime = qApp->styleHints()->cursorFlashTime();
        if(flashtime >= 2) m_blinktimer = this->startTimer(flashtime / 2);
    }

    this->onCursorBlink();
}

void CursorScrollArea::timerEvent(QTimerEvent* e)
{
    if(m_cursor && (e->timerId() == m_blinktimer))
    {
        RDCursor_Toggle(m_cursor);
        this->onCursorBlink();
    }

    QAbstractScrollArea::timerEvent(e);
}

void CursorScrollArea::mousePressEvent(QMouseEvent* e)
{
    if(m_cursor && (e->button() == Qt::BackButton)) RDCursor_GoBack(m_cursor);
    else if(m_cursor && (e->button() == Qt::ForwardButton)) RDCursor_GoForward(m_cursor);
    QAbstractScrollArea::mousePressEvent(e);
}

bool CursorScrollArea::event(QEvent* e)
{
    if(m_cursor && (e->type() == QEvent::FocusIn)) this->blinkCursor();
    else if(m_cursor && (e->type() == QEvent::FocusOut)) this->stopBlinkCursor();
    return QAbstractScrollArea::event(e);
}
