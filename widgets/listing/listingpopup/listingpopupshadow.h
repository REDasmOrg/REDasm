#pragma once

#include <QGraphicsEffect>

class ListingPopupShadow : public QGraphicsEffect
{
    Q_OBJECT

    public:
        explicit ListingPopupShadow(QObject *parent = nullptr);
        QRectF boundingRectFor(const QRectF& rect) const override;
        void setDistance(qreal distance);
        qreal distance() const;
        void setBlurRadius(qreal blurradius);
        qreal blurRadius() const;
        void setColor(const QColor& color);
        QColor color() const;

    protected:
        void draw(QPainter* painter) override;

    private:
        qreal m_distance;
        qreal m_blurradius;
        QColor m_color;
};

