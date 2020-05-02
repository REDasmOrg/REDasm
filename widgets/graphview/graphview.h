#pragma once

// Widget based on x64dbg's DisassemblerGraphView
// - https://github.com/x64dbg/x64dbg/blob/development/src/gui/Src/Gui/DisassemblerGraphView.h
// - https://github.com/x64dbg/x64dbg/blob/development/src/gui/Src/Gui/DisassemblerGraphView.cpp

#include <QVector>
#include <QList>
#include <unordered_map>
#include <utility>
#include <rdapi/rdapi.h>
#include <rdapi/graph/graph.h>
#include "../cursorscrollarea.h"
#include "../../hooks/idisassemblercommand.h"
#include "../../themeprovider.h"
#include "graphviewitem.h"

class GraphView : public CursorScrollArea
{
    Q_OBJECT

    public:
        explicit GraphView(IDisassemblerCommand* command, QWidget *parent = nullptr);
        void setGraph(RDGraph* graph);
        void setSelectedBlock(GraphViewItem* item);
        void setFocusOnSelection(bool b);
        GraphViewItem* selectedItem() const;
        RDGraph* graph() const;

    public slots:
        void focusSelectedBlock();

    protected:
        void focusBlock(const GraphViewItem* item, bool force = false);

    protected:
        void mouseDoubleClickEvent(QMouseEvent* e) override;
        void mousePressEvent(QMouseEvent* e) override;
        void mouseReleaseEvent(QMouseEvent* e) override;
        void mouseMoveEvent(QMouseEvent* e) override;
        void wheelEvent(QWheelEvent* e) override;
        void resizeEvent(QResizeEvent* e) override;
        void paintEvent(QPaintEvent*) override;
        void showEvent(QShowEvent* e) override;
        virtual void selectedItemChangedEvent();
        virtual void computeLayout();

    private:
        GraphViewItem* itemFromMouseEvent(QMouseEvent *e) const;
        void zoomOut(const QPoint& cursorpos);
        void zoomIn(const QPoint& cursorpos);
        void adjustSize(int vpw, int vph, const QPoint& cursorpos = QPoint(), bool fit = false);
        void precomputeArrow(const RDGraphEdge& e);
        void precomputeLine(const RDGraphEdge& e);
        bool updateSelectedItem(QMouseEvent* e);

    signals:
        void selectedItemChanged();

    protected:
        IDisassemblerCommand* m_command;
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
