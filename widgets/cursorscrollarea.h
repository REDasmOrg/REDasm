#pragma once

#include <QAbstractScrollArea>

class CursorScrollArea : public QAbstractScrollArea
{
    Q_OBJECT

    public:
        explicit CursorScrollArea(QWidget *parent = nullptr);

    protected:
        virtual void onCursorBlink();
        void mousePressEvent(QMouseEvent *e) override;
        bool event(QEvent* e) override;
};
