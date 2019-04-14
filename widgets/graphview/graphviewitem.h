#ifndef GRAPHVIEWITEM_H
#define GRAPHVIEWITEM_H

#include <QObject>
#include <QMouseEvent>
#include <QPainter>
#include <QRect>
#include <redasm/graph/graph.h>

class GraphViewItem: public QObject
{
    Q_OBJECT

    public:
        explicit GraphViewItem(const REDasm::Graphing::Node& node, QObject* parent = nullptr);
        virtual ~GraphViewItem() = default;
        const REDasm::Graphing::Node& node() const;
        int x() const;
        int y() const;
        int width() const;
        int height() const;
        QRect rect() const;
        bool contains(const QPoint& p) const;
        const QPoint& position() const;
        void move(const QPoint &pos);

    protected:
        virtual void mousePressEvent(QMouseEvent *e);
        virtual void invalidate(bool notify = true);

    public:
        QPoint mapToItem(const QPoint& p) const;
        virtual void render(QPainter* painter) = 0;
        virtual QSize size() const = 0;

    signals:
        void invalidated();

    private:
        QPoint m_pos;
        const REDasm::Graphing::Node& m_node;

    friend class GraphView;
};

#endif // GRAPHVIEWITEM_H
