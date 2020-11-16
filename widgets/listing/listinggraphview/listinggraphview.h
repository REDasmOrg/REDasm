#pragma once

#include <optional>
#include "../../graphview/graphview.h"
#include "../../../renderer/surfacedocument.h"

class ListingBlockItem;

class ListingGraphView : public GraphView, public ISurface
{
    Q_OBJECT

    public:
        explicit ListingGraphView(const RDContextPtr& ctx, QWidget *parent = nullptr);
        bool renderGraph(const RDDocumentItem* item);

    public: // ISurface interface
        void linkTo(ISurface* s) override;
        void unlink() override;
        void goBack() override;
        void goForward() override;
        void copy() const override;
        bool goToAddress(rd_address address) override;
        bool goTo(const RDDocumentItem* item) override;
        bool hasSelection() const override;
        bool canGoBack() const override;
        bool canGoForward() const override;
        bool getCurrentItem(RDDocumentItem* item) const override;
        bool getCurrentSymbol(RDSymbol* symbol) const override;
        SurfaceQt* surface() const override;
        QString currentWord() const override;
        const RDContextPtr& context() const override;
        QWidget* widget() override;

    private:
        void focusCurrentBlock();
        QColor getEdgeColor(const RDGraphEdge &e) const;
        QString getEdgeLabel(const RDGraphEdge &e) const;
        GraphViewItem* itemFromCurrentLine() const;

    protected:
        SurfaceQt* selectedSurface() const;
        void showEvent(QShowEvent* e) override;
        void computeEdge(const RDGraphEdge& e) override;
        void computeNode(GraphViewItem* item) override;
        GraphViewItem* createItem(RDGraphNode n, const RDGraph*g) override;
        void computed() override;

    private slots:
        void onFollowRequested();

    private:
        RDContextPtr m_context;
        SurfaceDocument* m_surface;
        std::optional<RDDocumentItem> m_currentfunction;
};
