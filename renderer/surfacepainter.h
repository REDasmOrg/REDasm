#pragma once

#include <QPixmap>
#include <QImage>
#include "../hooks/isurface.h"
#include "surfaceqt.h"

class SurfacePainter : public SurfaceQt
{
    Q_OBJECT

    public:
        explicit SurfacePainter(const RDContextPtr& ctx, rd_flag flags, QObject *parent = nullptr);
        const QPixmap& pixmap() const;

    protected:
        void render() override;

    private:
        QPixmap m_pixmap;
        QImage m_image;
};

