#ifndef THEMEPROVIDER_H
#define THEMEPROVIDER_H

#define THEME_ICON(n)  ThemeProvider::icon(n)
#define THEME_VALUE(n) ThemeProvider::themeValue(n)
#define THEME_VALUE_COLOR(n) THEME_VALUE(n).name()

#include <QJsonObject>
#include <QColor>
#include <QIcon>

class ThemeProvider
{
    public:
        ThemeProvider() = delete;
        ThemeProvider(const ThemeProvider&) = delete;

    public:
        static void loadTheme(const QString &theme);
        static bool isDarkTheme();
        static bool contains(const QString& name);
        static QColor themeValue(const QString& name);
        static QIcon icon(const QString& name);
        static QColor highlightColor();
        static QColor seekColor();
        static QColor dottedColor();

    public:
        static void selectDarkTheme();

    private:
        static bool m_darktheme;
        static QJsonObject m_theme;
};

#endif // THEMEPROVIDER_H
