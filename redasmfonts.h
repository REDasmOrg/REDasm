#pragma once

#include <QIconEngine>
#include <QFont>

class REDasmFontIconEngine: public QIconEngine
{
    public:
        REDasmFontIconEngine();
        void setFont(const QFont& font);
        void setLetter(const QString& letter);

    public:
        void paint(QPainter *painter, const QRect &rect, QIcon::Mode mode, QIcon::State) override;
        QPixmap pixmap(const QSize &size, QIcon::Mode mode, QIcon::State state) override;
        QIconEngine* clone() const override;

    private:
        QFont m_font;
        QString m_letter;
};

class REDasmFonts
{
    private:
        REDasmFonts();

    public:
        QFont faFont() const;
        QFont faBrandsFont() const;
        QIcon icon(const QChar& code);
        QIcon brand(const QChar& code);
        static REDasmFonts* instance();
};

#define FA_FONT        REDasmFonts::instance()->faFont()
#define FA_ICON(code)  REDasmFonts::instance()->icon(code)
#define FA_BRAND(code) REDasmFonts::instance()->brand(code)
