#pragma once

#include <QAbstractScrollArea>
#include <QFontMetrics>
#include <rdapi/rdapi.h>
#include "../../../hooks/isurface.h"
#include "../listingpopup/listingpopup.h"

class SurfacePainter;

class ListingTextWidget : public QAbstractScrollArea, public ISurface
{
    Q_OBJECT

    public:
        explicit ListingTextWidget(QWidget *parent = nullptr);
        void setContext(const RDContextPtr& ctx);

    public: // IDisassemblerCommand interface
        void goBack() override;
        void goForward() override;
        bool goTo(rd_address address) override;
        bool seek(rd_address address) override;
        bool hasSelection() const override;
        bool canGoBack() const override;
        bool canGoForward() const override;
        QString currentLabel(rd_address* address) const override;
        rd_address currentAddress() const override;
        SurfaceQt* surface() const override;
        QString currentWord() const override;
        const RDContextPtr& context() const override;
        QWidget* widget() override;
        void copy() const override;

    protected:
        void scrollContentsBy(int dx, int) override;
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

    Q_SIGNALS:
        void switchView();

    private:
        RDContextPtr m_context;
        SurfacePainter* m_surface{nullptr};
        RDDocument* m_document{nullptr};
        ListingPopup* m_disassemblerpopup{nullptr};
};
