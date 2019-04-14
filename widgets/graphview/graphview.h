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
#include "graphviewitem.h"

class GraphView : public QAbstractScrollArea
{
    Q_OBJECT

    public:
        explicit GraphView(QWidget *parent = nullptr);
        void setDisassembler(const REDasm::DisassemblerPtr &disassembler);
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
        virtual void showEvent(QShowEvent* e);
        virtual void computeLayout();

    private:
        GraphViewItem* itemFromMouseEvent(QMouseEvent *e) const;
        void zoomOut(const QPoint& cursorpos);
        void zoomIn(const QPoint& cursorpos);
        void adjustSize(int vpw, int vph, const QPoint& cursorpos = QPoint(), bool fit = false);
        void precomputeArrow(const REDasm::Graphing::Edge& e);
        void precomputeLine(const REDasm::Graphing::Edge& e);

    protected:
        REDasm::DisassemblerPtr m_disassembler;
        QHash<REDasm::Graphing::Node, GraphViewItem*> m_items;

    private:
        GraphViewItem* m_selecteditem;
        std::unique_ptr<REDasm::Graphing::Graph> m_graph;
        std::unordered_map< REDasm::Graphing::Edge, QVector<QLine> > m_lines;
        std::unordered_map<REDasm::Graphing::Edge, QPolygon> m_arrows;
        QPoint m_renderoffset, m_scrollbase;
        QSize m_rendersize;
        float m_scalefactor, m_scalestep, m_prevscalefactor;
        float m_scalemin, m_scalemax;
        int m_scaledirection, m_scaleboost;
        bool m_viewportready, m_scrollmode;
};

#endif // GRAPHVIEW_H
