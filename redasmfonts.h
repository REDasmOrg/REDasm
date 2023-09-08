#pragma once

#include <QIconEngine>
#include <QFont>

class REDasmFontIconEngine: public QIconEngine
{
    public:
        REDasmFontIconEngine();
        void setFont(const QFont& font);
        void setLetter(const QString& letter);
        void setColor(const QColor& color);

    public:
        void paint(QPainter *painter, const QRect &rect, QIcon::Mode mode, QIcon::State) override;
        QPixmap pixmap(const QSize &size, QIcon::Mode mode, QIcon::State state) override;
        QIconEngine* clone() const override;

    private:
        QFont m_font;
        QString m_letter;
        QColor m_color;
};

class REDasmFonts
{
    private:
        REDasmFonts();

    public:
        QFont faFont() const;
        QFont faBrandsFont() const;
        QIcon icon(const QChar& code, const QColor& color);
        QIcon icon(const QChar& code);
        QIcon brand(const QChar& code, const QColor& color);
        QIcon brand(const QChar& code);
        static REDasmFonts* instance();

    private:
        QStringList m_fafamilies, m_fabfamilies;
};

#define FA_FONT                     REDasmFonts::instance()->faFont()
#define FAB_FONT                    REDasmFonts::instance()->faBrandsFont()
#define FA_ICON(code)               REDasmFonts::instance()->icon(QChar{code})
#define FA_ICON_COLOR(code, color)  REDasmFonts::instance()->icon(QChar{code}, color)
#define FAB_ICON(code)              REDasmFonts::instance()->brand(QChar{code})
#define FAB_ICON_COLOR(code, color) REDasmFonts::instance()->brand(QChar{code}, color)
