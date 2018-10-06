#ifndef THEMEPROVIDER_H
#define THEMEPROVIDER_H

#define THEME_VALUE(n) ThemeProvider::themeValue(n)
#define THEME_VALUE_COLOR(n) THEME_VALUE(n).name()

#include <QJsonObject>
#include <QColor>

class ThemeProvider
{
    private:
        ThemeProvider();
        static void loadTheme(const QString &theme);

    public:
        static bool contains(const QString& name);
        static QColor themeValue(const QString& name);
        static QColor highlightColor();
        static QColor seekColor();
        static QColor dottedColor();

    private:
        static QJsonObject _theme;
};

#endif // THEMEPROVIDER_H
