#pragma once

#include "surfaceqt.h"

class QTextDocument;

class SurfaceDocument : public SurfaceQt
{
    Q_OBJECT

    public:
        explicit SurfaceDocument(const RDContextPtr& ctx, rd_flag flags, QObject *parent = nullptr);
        void renderTo(QPainter* painter);

    protected:
        void render() override;

    private:
        QTextDocument* m_document;
};

