#ifndef THEMEPROVIDER_H
#define THEMEPROVIDER_H

#define THEME_VALUE(name) ThemeProvider::themeValue(name)

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
