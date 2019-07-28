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
        enum: size_t { None = 0, Selected, Focused };

    public:
        explicit GraphViewItem(REDasm::Node node, QObject* parent = nullptr);
        virtual ~GraphViewItem() = default;
        virtual void invalidate(bool notify = true);
        REDasm::Node node() const;
        int x() const;
        int y() const;
        int width() const;
        int height() const;
        QRect rect() const;
        bool contains(const QPoint& p) const;
        const QPoint& position() const;
        void move(const QPoint &pos);

    protected:
        virtual void itemSelectionChanged(bool selected);
        virtual void mouseDoubleClickEvent(QMouseEvent *e);
        virtual void mousePressEvent(QMouseEvent *e);
        virtual void mouseMoveEvent(QMouseEvent *e);

    public:
        QPoint mapToItem(const QPoint& p) const;
        virtual int currentLine() const;
        virtual void render(QPainter* painter, size_t state) = 0;
        virtual QSize size() const = 0;

    signals:
        void invalidated();
        void menuRequested();

    private:
        QPoint m_pos;
        REDasm::Node m_node;

    friend class GraphView;
};

#endif // GRAPHVIEWITEM_H
