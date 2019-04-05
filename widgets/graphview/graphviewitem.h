#ifndef GRAPHVIEWITEM_H
#define GRAPHVIEWITEM_H

#include <QObject>
#include <QPainter>
#include <QRect>
#include <QSize>
#include <QSize>

class GraphViewItem: public QObject
{
    Q_OBJECT

    public:
        explicit GraphViewItem(QObject* parent = nullptr);
        int x() const;
        int y() const;
        int width() const;
        int height() const;
        bool contains(const QPoint& p) const;
        const QPoint& position() const;
        void move(const QPoint &pos);

    protected:
        QPoint mapToItem(const QPoint& p) const;

    public:
        virtual void render(QPainter* painter) = 0;
        virtual QSize size() const = 0;

    private:
        QPoint m_pos;
};

#endif // GRAPHVIEWITEM_H
