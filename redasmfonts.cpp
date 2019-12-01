#include "redasmfonts.h"
#include <QFontDatabase>
#include <QApplication>
#include <QPalette>
#include <QPainter>
#include <QIcon>

REDasmFontIconEngine::REDasmFontIconEngine(): QIconEngine() { }
void REDasmFontIconEngine::setFont(const QFont& font) { m_font = font; }
void REDasmFontIconEngine::setLetter(const QString& letter) { m_letter = letter; }

void REDasmFontIconEngine::paint(QPainter* painter, const QRect& rect, QIcon::Mode mode, QIcon::State)
{
    QFont font = m_font;
    int drawsize = qRound(rect.height() * 0.8);
    font.setPixelSize(drawsize);

    QColor pc = qApp->palette().color(QPalette::Normal, QPalette::ButtonText);
    if(mode == QIcon::Disabled) pc = qApp->palette().color(QPalette::Disabled, QPalette::ButtonText);
    if(mode == QIcon::Selected) pc = qApp->palette().color(QPalette::Active, QPalette::ButtonText);

    painter->save();
        painter->setPen(QPen(pc));
        painter->setFont(font);
        painter->drawText(rect, Qt::AlignCenter | Qt::AlignVCenter, m_letter);
    painter->restore();
}

QPixmap REDasmFontIconEngine::pixmap(const QSize& size, QIcon::Mode mode, QIcon::State state)
{
    QPixmap pixmap(size);
    pixmap.fill(Qt::transparent);

    QPainter painter(&pixmap);
    this->paint(&painter, QRect(QPoint(0, 0), size), mode, state);
    return pixmap;
}

QIconEngine* REDasmFontIconEngine::clone() const
{
    auto* engine = new REDasmFontIconEngine();
    engine->setFont(m_font);
    return engine;
}

REDasmFonts::REDasmFonts()
{
    QFontDatabase::addApplicationFont(":/res/fonts/FontAwesomeBrands.otf");
    QFontDatabase::addApplicationFont(":/res/fonts/FontAwesome.otf");
}

QFont REDasmFonts::faFont() const { return QFont("FontAwesome"); }
QFont REDasmFonts::faBrandsFont() const { return QFont("FontAwesomeBrands"); }

QIcon REDasmFonts::icon(const QChar& code)
{
    auto* engine = new REDasmFontIconEngine();
    engine->setFont(this->faFont());
    engine->setLetter(code);
    return QIcon(engine);
}

QIcon REDasmFonts::brand(const QChar& code)
{
    auto* engine = new REDasmFontIconEngine();
    engine->setFont(this->faBrandsFont());
    engine->setLetter(code);
    return QIcon(engine);
}

REDasmFonts* REDasmFonts::instance()
{
    static REDasmFonts instance;
    return &instance;
}
