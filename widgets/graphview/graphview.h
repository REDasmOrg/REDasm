#ifndef GRAPHVIEW_H
#define GRAPHVIEW_H

// Widget based on x64dbg's DisassemblerGraphView
// - https://github.com/x64dbg/x64dbg/blob/development/src/gui/Src/Gui/DisassemblerGraphView.h
// - https://github.com/x64dbg/x64dbg/blob/development/src/gui/Src/Gui/DisassemblerGraphView.cpp

#include <QAbstractScrollArea>
#include <QVector>
#include <QList>
#include <redasm/disassembler/disassemblerapi.h>
#include <redasm/graph/graph.h>
#include "../../../themeprovider.h"

class GraphViewItem: public QObject
{
    Q_OBJECT

    public:
        explicit GraphViewItem(QObject* parent = nullptr): QObject(parent) { }
        int x() const { return this->position().x(); }
        int y() const { return this->position().y(); }
        int width() const { return this->size().width(); }
        int height() const { return this->size().height(); }
        const QPoint& position() const { return m_pos; }
        void move(const QPoint &pos) { m_pos = pos; };

    public:
        virtual void render(QPainter* painter) = 0;
        virtual QSize size() const = 0;

    private:
        QPoint m_pos;
};

class GraphView : public QAbstractScrollArea
{
    Q_OBJECT

    public:
        explicit GraphView(QWidget *parent = nullptr);
        void setDisassembler(REDasm::DisassemblerAPI* disassembler);
        void setGraph(REDasm::Graphing::Graph* graph);
        REDasm::Graphing::Graph* graph() const;

    protected:
        void focusBlock(const GraphViewItem* item);

    protected:
        virtual void mousePressEvent(QMouseEvent* e);
        virtual void mouseReleaseEvent(QMouseEvent* e);
        virtual void mouseMoveEvent(QMouseEvent* e);
        virtual void wheelEvent(QWheelEvent* e);
        virtual void resizeEvent(QResizeEvent* e);
        virtual void paintEvent(QPaintEvent* e);
        virtual void computeLayout();

    private:
        void zoomOut(const QPoint& cursorpos);
        void zoomIn(const QPoint& cursorpos);
        void adjustSize(int vpw, int vph, const QPoint& cursorpos = QPoint(), bool fit = false);
        void precomputeArrow(const REDasm::Graphing::Edge& e);
        void precomputeLine(const REDasm::Graphing::Edge& e);

    protected:
        REDasm::DisassemblerAPI* m_disassembler;
        QHash<REDasm::Graphing::Node, GraphViewItem*> m_items;

    private:
        std::unique_ptr<REDasm::Graphing::Graph> m_graph;
        std::unordered_map< REDasm::Graphing::Edge, QVector<QLine> > m_lines;
        std::unordered_map<REDasm::Graphing::Edge, QPolygon> m_arrows;
        QPoint m_renderoffset, m_scrollbase;
        QSize m_rendersize;
        float m_scalefactor, m_scalestep, m_prevscalefactor;
        int m_scaledirection, m_scaleboost;
        bool m_scrollmode;
};

#endif // GRAPHVIEW_H
