#pragma once

// Widget based on x64dbg's DisassemblerGraphView
// - https://github.com/x64dbg/x64dbg/blob/development/src/gui/Src/Gui/DisassemblerGraphView.h
// - https://github.com/x64dbg/x64dbg/blob/development/src/gui/Src/Gui/DisassemblerGraphView.cpp

#include <QAbstractScrollArea>
#include <QVector>
#include <QList>
#include <unordered_map>
#include <utility>
#include <rdapi/rdapi.h>
#include <rdapi/graph/graph.h>
#include "../../themeprovider.h"
#include "graphviewitem.h"

class GraphView : public QAbstractScrollArea
{
    Q_OBJECT

    public:
        explicit GraphView(QWidget *parent = nullptr);
        void setGraph(RDGraph* graph);
        void setSelectedBlock(GraphViewItem* item);
        void setFocusOnSelection(bool b);
        void updateGraph();
        GraphViewItem* selectedItem() const;
        RDGraph* graph() const;

    public Q_SLOTS:
        void focusSelectedBlock();

    protected:
        void mouseDoubleClickEvent(QMouseEvent* e) override;
        void mousePressEvent(QMouseEvent* e) override;
        void mouseReleaseEvent(QMouseEvent* e) override;
        void mouseMoveEvent(QMouseEvent* e) override;
        void wheelEvent(QWheelEvent* event) override;
        void resizeEvent(QResizeEvent* e) override;
        void paintEvent(QPaintEvent*) override;
        void showEvent(QShowEvent* e) override;
        void focusBlock(const GraphViewItem* item, bool force = false);
        virtual void selectedItemChangedEvent();
        virtual GraphViewItem* createItem(RDGraphNode n, const RDGraph* g) = 0;
        virtual void computeEdge(const RDGraphEdge&);
        virtual void computeNode(GraphViewItem*);
        virtual void computeLayout();
        virtual void computed();

    private:
        GraphViewItem* itemFromMouseEvent(QMouseEvent *e, QPoint* itempos = nullptr) const;
        void zoomOut(const QPointF& cursorpos);
        void zoomIn(const QPointF& cursorpos);
        void adjustSize(int vpw, int vph, const QPointF& cursorpos = QPoint(), bool fit = false);
        void precomputeArrow(const RDGraphEdge& e);
        void precomputeLine(const RDGraphEdge& e);
        bool updateSelectedItem(QMouseEvent* e, QPoint* itempos = nullptr);

    Q_SIGNALS:
        void selectedItemChanged();

    protected:
        RDGraph* m_graph{nullptr};
        QHash<RDGraphNode, GraphViewItem*> m_items;

    private:
        GraphViewItem* m_selecteditem{nullptr};
        std::unordered_map<RDGraphEdge, QVector<QLine>> m_lines;
        std::unordered_map<RDGraphEdge, QPolygon> m_arrows;
        QPoint m_renderoffset, m_scrollbase;
        QSize m_rendersize;
        qreal m_scalefactor{1.0}, m_scalestep{0.1}, m_prevscalefactor{0};
        qreal m_scalemin{0}, m_scalemax{5.0};
        int m_scaledirection{0}, m_scaleboost{1};
        bool m_viewportready{false}, m_scrollmode{true};
        bool m_focusonselection{false};
};
