#pragma once

#include <optional>
#include "../graphview/graphview.h"
#include "../../hooks/idisassemblercommand.h"

class DisassemblerBlockItem;

class DisassemblerGraphView : public GraphView, public IDisassemblerCommand
{
    Q_OBJECT

    public:
        explicit DisassemblerGraphView(IDisassemblerCommand* command, QWidget *parent = nullptr);

    public: // IDisassemblerCommand interface
        void goBack() override;
        void goForward() override;
        void copy() const override;
        bool gotoAddress(rd_address address) override;
        bool gotoItem(const RDDocumentItem& item) override;
        bool hasSelection() const override;
        bool canGoBack() const override;
        bool canGoForward() const override;
        bool getCurrentItem(RDDocumentItem* item) const override;
        bool getSelectedSymbol(RDSymbol* symbol) const override;
        bool ownsCursor(const RDCursor* cursor) const override;
        const RDCursorPos* currentPosition() const override;
        const RDCursorPos* currentSelection() const override;
        QString currentWord() const override;
        RDDisassembler* disassembler() const override;
        RDCursor* cursor() const override;
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
        void onCursorBlink() override;
        void showEvent(QShowEvent* e) override;
        void computeLayout() override;

    private slots:
        void onFollowRequested(DisassemblerBlockItem* block);

    private:
        IDisassemblerCommand* m_command;
        std::optional<RDDocumentItem> m_currentfunction;
        QMenu* m_contextmenu{nullptr};
};
