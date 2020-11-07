#pragma once

#include <optional>
#include "../graphview/graphview.h"
#include "../../hooks/icommand.h"

class ListingBlockItem;

class ListingGraphView : public GraphView, public ICommand
{
    Q_OBJECT

    public:
        explicit ListingGraphView(ICommand* command, QWidget *parent = nullptr);

    public: // IDisassemblerCommand interface
        void goBack() override;
        void goForward() override;
        void copy() const override;
        bool goToAddress(rd_address address) override;
        bool goTo(const RDDocumentItem& item) override;
        bool hasSelection() const override;
        bool canGoBack() const override;
        bool canGoForward() const override;
        bool getCurrentItem(RDDocumentItem* item) const override;
        bool getCurrentSymbol(RDSymbol* symbol) const override;
        const RDSurfacePos* position() const override;
        const RDSurfacePos* selection() const override;
        SurfaceQt* surface() const override;
        QString currentWord() const override;
        const RDContextPtr& context() const override;
        QWidget* widget() override;

    public slots:
        bool renderGraph();

    private:
        void focusCurrentBlock();
        bool updateGraph(rd_address address);
        QColor getEdgeColor(const RDGraphEdge &e) const;
        QString getEdgeLabel(const RDGraphEdge &e) const;
        GraphViewItem* itemFromCurrentLine() const;

    protected:
        void showEvent(QShowEvent* e) override;
        void computeEdge(const RDGraphEdge& e) override;
        void computeNode(GraphViewItem* item) override;
        GraphViewItem* createItem(RDGraphNode n, const RDGraph* g) override;
        void computed() override;

    private slots:
        void onFollowRequested(ListingBlockItem* block);

    private:
        ICommand* m_command;
        std::optional<RDDocumentItem> m_currentfunction;
        QMenu* m_contextmenu{nullptr};
};
