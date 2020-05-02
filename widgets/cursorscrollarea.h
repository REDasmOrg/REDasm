#pragma once

#include <QAbstractScrollArea>

struct RDCursor;

class CursorScrollArea : public QAbstractScrollArea
{
    Q_OBJECT

    public:
        explicit CursorScrollArea(QWidget *parent = nullptr);
        ~CursorScrollArea();

    protected:
        void setBlinkCursor(RDCursor* cursor);
        void blinkCursor();
        void timerEvent(QTimerEvent* e) override;
        void mousePressEvent(QMouseEvent *e) override;
        bool event(QEvent* e) override;
        virtual void onCursorBlink();

    private:
        RDCursor* m_cursor{nullptr};
        int m_blinktimer{0};
};
