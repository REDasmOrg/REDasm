#pragma once

#include <QObject>
#include <QColor>
#include <QSizeF>
#include <rdapi/rdapi.h>
#include "../hooks/isurface.h"

class QFontMetricsF;

class SurfaceQt : public QObject
{
    Q_OBJECT

    public:
        explicit SurfaceQt(const RDContextPtr& ctx, rd_flag flags, QObject *parent = nullptr);
        ~SurfaceQt();
        int scrollLength() const;
        int scrollValue() const;
        int rows() const;
        QSize size() const;
        const QColor& baseColor() const;
        const RDContextPtr& context() const;
        QWidget* widget() const;
        RDSurface* handle() const;
        void activateCursor(bool activate);
        bool canGoBack() const;
        bool canGoForward() const;
        bool hasSelection() const;
        bool getCurrentItem(RDDocumentItem* item) const;
        bool getCurrentSymbol(RDSymbol* symbol) const;
        bool getSymbolAt(const QPointF& pt, RDSymbol* symbol) const;
        const char* getCurrentWord() const;
        const RDSurfacePos* selection() const;
        const RDSurfacePos* position() const;
        RDSurfacePos mapPoint(const QPointF& pt) const;
        bool seek(const RDDocumentItem* item);
        bool goTo(const RDDocumentItem* item);
        bool goToAddress(rd_address address);
        void goBack();
        void goForward();
        void setBaseColor(const QColor& c);
        void scroll(int nrows, int ncols);
        void moveTo(int row, int col);
        void moveTo(const QPointF& pt);
        void select(int row, int col);
        void select(const QPointF& pt);
        void selectAt(const QPointF& pt);
        void resize(int row, int cols);
        void resize();
        void linkTo(SurfaceQt* s);
        void unlink();
        void copy() const;

    protected:
        QColor getBackground(const RDSurfaceCell* cell) const;
        QColor getForeground(const RDSurfaceCell* cell) const;
        const QSizeF& cellSize() const;
        qreal cellWidth() const;
        qreal cellHeight() const;
        QFontMetricsF fontMetrics() const;
        virtual void render() = 0;

    private:
        void resize(const QSizeF& size);

    signals:
        void renderCompleted();
        void positionChanged();
        void scrollChanged();
        void historyChanged();

    private:
        QColor m_basecolor;
        QSizeF m_cellsize;
        rd_ptr<RDSurface> m_surface;
        RDContextPtr m_context;
};

