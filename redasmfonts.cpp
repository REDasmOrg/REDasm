#include "redasmfonts.h"
#include <QFontDatabase>
#include <QApplication>
#include <QPalette>
#include <QPainter>
#include <QIcon>

REDasmFontIconEngine::REDasmFontIconEngine(): QIconEngine() { }
void REDasmFontIconEngine::setFont(const QFont& font) { m_font = font; }
void REDasmFontIconEngine::setLetter(const QString& letter) { m_letter = letter; }
void REDasmFontIconEngine::setColor(const QColor& color) { m_color = color; }

void REDasmFontIconEngine::paint(QPainter* painter, const QRect& rect, QIcon::Mode mode, QIcon::State)
{
    QFont font = m_font;
    int drawsize = qRound(rect.height() * 0.8);
    font.setPixelSize(drawsize);

    QColor pc = m_color;
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
    int id = QFontDatabase::addApplicationFont(":/res/fonts/FontAwesomeBrands.otf");
    if(id != -1) m_fabfamilies = QFontDatabase::applicationFontFamilies(id);

    id = QFontDatabase::addApplicationFont(":/res/fonts/FontAwesome.otf");
    if(id != -1) m_fafamilies = QFontDatabase::applicationFontFamilies(id);
}

QFont REDasmFonts::faFont() const { QFont f(m_fafamilies.front()); f.setStyleStrategy(QFont::NoFontMerging); return f; }
QFont REDasmFonts::faBrandsFont() const { QFont f(m_fabfamilies.front()); f.setStyleStrategy(QFont::NoFontMerging); return f; }

QIcon REDasmFonts::icon(const QChar& code, const QColor& color)
{
    auto* engine = new REDasmFontIconEngine();
    engine->setFont(this->faFont());
    engine->setLetter(code);
    engine->setColor(color);
    return QIcon(engine);
}

QIcon REDasmFonts::icon(const QChar& code) { return this->icon(code, qApp->palette().color(QPalette::Normal, QPalette::ButtonText)); }

QIcon REDasmFonts::brand(const QChar& code, const QColor& color)
{
    auto* engine = new REDasmFontIconEngine();
    engine->setFont(this->faBrandsFont());
    engine->setLetter(code);
    engine->setColor(color);
    return QIcon(engine);
}

QIcon REDasmFonts::brand(const QChar& code)
{
    return this->brand(code, qApp->palette().color(QPalette::Normal, QPalette::ButtonText));
}

REDasmFonts* REDasmFonts::instance()
{
    static REDasmFonts instance;
    return &instance;
}
