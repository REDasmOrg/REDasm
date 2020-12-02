#include "listingpopupshadow.h"
#include <QPainter>

QT_BEGIN_NAMESPACE
extern Q_WIDGETS_EXPORT void qt_blurImage(QPainter *p, QImage &blurImage, qreal radius, bool quality, bool alphaOnly, int transposed = 0);
QT_END_NAMESPACE

ListingPopupShadow::ListingPopupShadow(QObject *parent) : QGraphicsEffect(parent), m_distance(4.0f), m_blurradius(10.0f), m_color(0, 0, 0, 80) { }
void ListingPopupShadow::setDistance(qreal distance) { m_distance = distance; this->updateBoundingRect(); }
qreal ListingPopupShadow::distance() const { return m_distance; }
void ListingPopupShadow::setBlurRadius(qreal blurradius) { m_blurradius = blurradius; this->updateBoundingRect(); }
qreal ListingPopupShadow::blurRadius() const { return m_blurradius; }
void ListingPopupShadow::setColor(const QColor& color) { m_color = color; }
QColor ListingPopupShadow::color() const { return m_color; }

void ListingPopupShadow::draw(QPainter* painter)
{
    if((m_blurradius + m_distance) <= 0)
    {
        this->drawSource(painter);
        return;
    }

    PixmapPadMode mode = QGraphicsEffect::PadToEffectiveBoundingRect;
    QPoint offset;
    const QPixmap px = this->sourcePixmap(Qt::DeviceCoordinates, &offset, mode);
    if (px.isNull()) return;

    QTransform oldtransform = painter->worldTransform();
    painter->setWorldTransform(QTransform());

    QSize szi(px.size().width() + 2 * m_distance, px.size().height() + 2 * m_distance);

    QImage tmp(szi, QImage::Format_ARGB32_Premultiplied);
    QPixmap scaled = px.scaled(szi);
    tmp.fill(0);

    QPainter tmppainter(&tmp);
    tmppainter.setCompositionMode(QPainter::CompositionMode_Source);
    tmppainter.drawPixmap(QPointF(-m_distance, -m_distance), scaled);
    tmppainter.end();

    QImage blurred(tmp.size(), QImage::Format_ARGB32_Premultiplied);
    blurred.fill(0);
    QPainter blurpainter(&blurred);
    qt_blurImage(&blurpainter, tmp, m_blurradius, false, true);
    blurpainter.end();

    tmp = blurred;

    tmppainter.begin(&tmp);
    tmppainter.setCompositionMode(QPainter::CompositionMode_SourceIn);
    tmppainter.fillRect(tmp.rect(), m_color);
    tmppainter.end();

    painter->drawImage(offset, tmp);
    painter->drawPixmap(offset, px, QRectF());
    painter->setWorldTransform(oldtransform);
}

QRectF ListingPopupShadow::boundingRectFor(const QRectF& rect) const
{
    qreal delta = m_blurradius + m_distance;
    return rect.united(rect.adjusted(-delta, -delta, delta, delta));
}
