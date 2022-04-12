#pragma once

#include "../../graphview/graphview.h"
#include "../../../renderer/surfacedocument.h"

class ListingBlockItem;

class ListingGraphView : public GraphView, public ISurface
{
    Q_OBJECT

    public:
        explicit ListingGraphView(const RDContextPtr& ctx, QWidget *parent = nullptr);
        bool renderGraph(rd_address address);

    public: // ISurface interface
        void goBack() override;
        void goForward() override;
        void copy() const override;
        bool goTo(rd_address address) override;
        bool seek(rd_address address) override;
        bool hasSelection() const override;
        bool canGoBack() const override;
        bool canGoForward() const override;
        SurfaceQt* surface() const override;
        QString currentWord() const override;
        rd_address currentAddress() const override;
        QString currentLabel(rd_address* address) const override;
        const RDContextPtr& context() const override;
        QWidget* widget() override;

    private:
        void focusCurrentBlock();
        QColor getEdgeColor(const RDGraphEdge &e) const;
        QString getEdgeLabel(const RDGraphEdge &e) const;
        GraphViewItem* itemFromCurrentLine() const;

    protected:
        void showEvent(QShowEvent* e) override;
        void computeEdge(const RDGraphEdge& e) override;
        void computeNode(GraphViewItem* item) override;
        GraphViewItem* createItem(RDGraphNode n, const RDGraph* g) override;
        void computed() override;

    private Q_SLOTS:
        void onFollowRequested();

    private:
        RDContextPtr m_context;
        SurfaceQt* m_surface;
};
