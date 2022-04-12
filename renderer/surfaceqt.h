#pragma once

#include <QObject>
#include <QColor>
#include <QSizeF>
#include <rdapi/rdapi.h>
#include "../hooks/isurface.h"

class QFontMetricsF;
class QPainter;

class SurfaceQt : public QObject
{
    Q_OBJECT

    public:
        explicit SurfaceQt(const RDContextPtr& ctx, rd_flag flags, QObject *parent = nullptr);
        ~SurfaceQt();
        void renderRange(QPainter* painter, rd_address startaddress, rd_address endaddress);
        bool contains(rd_address address) const;
        int rows() const;
        int indexOf(rd_address address) const;
        int lastIndexOf(rd_address address) const;
        QSize rangeSize(rd_address startaddress, rd_address endaddress) const;
        QSize size() const;
        const QColor& baseColor() const;
        const RDContextPtr& context() const;
        QWidget* widget() const;
        RDSurface* handle() const;
        rd_address firstAddress() const;
        rd_address lastAddress() const;
        rd_address currentAddress() const;
        qreal cellWidth() const;
        qreal cellHeight() const;
        void activateCursor(bool activate);
        bool canGoBack() const;
        bool canGoForward() const;
        bool hasSelection() const;
        QString getCurrentLabel(rd_address* address) const;
        bool getLabelAt(const QPointF& pt, rd_address* address) const;
        const char* getCurrentWord() const;
        RDSurfacePos selection() const;
        RDSurfacePos position() const;
        RDSurfacePos mapPoint(const QPointF& pt) const;
        bool seek(rd_address address);
        bool goTo(rd_address address);
        void getScrollRange(rd_address* start, rd_address* end) const;
        void goBack();
        void goForward();
        void setBaseColor(const QColor& c);
        void scroll(int nx, int ny);
        void moveTo(int row, int col);
        void moveTo(const QPointF& pt);
        void select(int row, int col);
        void select(const QPointF& pt);
        void selectAt(const QPointF& pt);
        void resizeRange(rd_address startaddress, rd_address endaddress, int cols);
        void resize(int row, int cols);
        void resize();
        void copy() const;

    protected:
        QColor getBackground(const RDSurfaceCell* cell) const;
        QColor getForeground(const RDSurfaceCell* cell) const;
        const QSizeF& cellSize() const;
        QFontMetricsF fontMetrics() const;
        virtual void render();

    private:
        void resize(const QSizeF& size);

    Q_SIGNALS:
        void renderCompleted();
        void addressChanged();
        void historyChanged();

    private:
        QColor m_basecolor;
        QSizeF m_cellsize;
        rd_ptr<RDSurface> m_surface;
        RDContextPtr m_context;
};

