#ifndef GRAPHITEM_H
#define GRAPHITEM_H

#include <QObject>
#include <QPainter>
#include <QPoint>

class GraphItem : public QObject
{
    Q_OBJECT

    public:
        explicit GraphItem(QObject *parent = nullptr);
        QColor borderColor() const;
        QRect rect() const;
        const QPoint& position() const;
        void move(int x, int y);

    public:
        virtual QSize size() const = 0;
        virtual void paint(QPainter* painter) = 0;

    private:
        QPoint _pos;

};

#endif // GRAPHITEM_H
