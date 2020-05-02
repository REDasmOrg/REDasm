#pragma once

#include <QAbstractScrollArea>
#include <QList>
#include <optional>
#include "disassemblerblockitem.h"
#include "../graphview/graphview.h"

class DisassemblerGraphView : public GraphView
{
    Q_OBJECT

    public:
        explicit DisassemblerGraphView(IDisassemblerCommand* command, QWidget *parent = nullptr);
        virtual ~DisassemblerGraphView();
        bool isCursorInGraph() const;

    public slots:
        void goTo(address_t address);
        void focusCurrentBlock();
        bool renderGraph();

    private:
        QColor getEdgeColor(const RDGraphEdge &e) const;
        QString getEdgeLabel(const RDGraphEdge &e) const;
        GraphViewItem* itemFromCurrentLine() const;

    protected:
        void onCursorBlink() override;
        void mousePressEvent(QMouseEvent *e) override;
        void mouseMoveEvent(QMouseEvent *e) override;
        void showEvent(QShowEvent* e) override;
        void selectedItemChangedEvent() override;
        void computeLayout() override;

    private slots:
        void onFollowRequested(const QPointF &localpos);
        void onMenuRequested();

    private:
        std::optional<RDDocumentItem> m_currentfunction;
};
