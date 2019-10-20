#ifndef THEMEPROVIDER_H
#define THEMEPROVIDER_H

#define THEME_ICON(n)  ThemeProvider::icon(n)
#define THEME_VALUE(n) ThemeProvider::themeValue(n)
#define THEME_VALUE_COLOR(n) THEME_VALUE(n).name()

#include <QJsonObject>
#include <QTableView>
#include <QColor>
#include <QIcon>

class ThemeProvider
{
    public:
        ThemeProvider() = delete;
        ThemeProvider(const ThemeProvider&) = delete;

    public:
        static QStringList uiThemes();
        static QStringList themes();
        static QString uiTheme(const QString& name);
        static QString theme(const QString& name);
        static bool contains(const QString& name);
        static bool isDarkTheme();
        static QColor themeValue(const QString& name);
        static QIcon icon(const QString& name);
        static QColor seekColor();
        static QColor dottedColor();
        static void styleCornerButton(QTableView* tableview);
        static void applyTheme();

    private:
        static bool loadTheme(const QString &theme);
        static QStringList readThemes(const QString& path);

    private:
        static QJsonObject m_theme;
};

#endif // THEMEPROVIDER_H
