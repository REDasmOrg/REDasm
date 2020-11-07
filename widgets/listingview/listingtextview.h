#pragma once

#include <QAbstractScrollArea>
#include <QFontMetrics>
#include <QMenu>
#include <rdapi/rdapi.h>
#include "../../hooks/icommand.h"
#include "../listingpopup/listingpopup.h"

class SurfacePainter;

class ListingTextView : public QAbstractScrollArea, public ICommand
{
    Q_OBJECT

    public:
        explicit ListingTextView(QWidget *parent = nullptr);
        void setContext(const RDContextPtr& ctx);

    public: // IDisassemblerCommand interface
        void goBack() override;
        void goForward() override;
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
        void copy() const override;

    protected:
        void scrollContentsBy(int dx, int dy) override;
        void focusInEvent(QFocusEvent *event) override;
        void focusOutEvent(QFocusEvent *event) override;
        void paintEvent(QPaintEvent* event) override;
        void resizeEvent(QResizeEvent* event) override;
        void mousePressEvent(QMouseEvent* event) override;
        void mouseMoveEvent(QMouseEvent* event) override;
        void mouseDoubleClickEvent(QMouseEvent* event) override;
        void wheelEvent(QWheelEvent *event) override;
        void keyPressEvent(QKeyEvent *event) override;
        bool event(QEvent* event) override;

    private:
        bool followUnderCursor();
        void adjustScrollBars();
        void showPopup(const QPointF& pt);

    signals:
        void switchView();

    private:
        RDContextPtr m_context;
        SurfacePainter* m_surface{nullptr};
        RDDocument* m_document{nullptr};
        ListingPopup* m_disassemblerpopup{nullptr};
        QMenu* m_contextmenu{nullptr};
};
