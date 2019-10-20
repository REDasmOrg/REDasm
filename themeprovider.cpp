#include "themeprovider.h"
#include <QApplication>
#include <QJsonDocument>
#include <QPalette>
#include <QVariant>
#include <QFile>
#include <QDir>
#include "redasmsettings.h"

#define THEME_UI_SET_COLOR(palette, key) if(m_theme.contains(#key)) palette.setColor(QPalette::key, m_theme[#key].toString())

QJsonObject ThemeProvider::m_theme;

QStringList ThemeProvider::themes() { return ThemeProvider::readThemes(":/themes");  }
QString ThemeProvider::theme(const QString &name) { return QString(":/themes/%1.json").arg(name.toLower()); }

bool ThemeProvider::isDarkTheme()
{
    if(!m_theme.contains("dark"))
        return false;

    return m_theme["dark"] == true;
}

bool ThemeProvider::loadTheme(const QString& theme)
{
    if(!m_theme.isEmpty())
        return true;

    QFile f(QString(":/themes/%1.json").arg(theme.toLower()));

    if(!f.open(QFile::ReadOnly))
        return false;

    QJsonDocument doc = QJsonDocument::fromJson(f.readAll());

    if(doc.isObject())
        m_theme = doc.object();
    else
        return false;

    return true;
}

QColor ThemeProvider::themeValue(const QString &name)
{
    if(m_theme.isEmpty())
    {
        REDasmSettings settings;

        if(!ThemeProvider::loadTheme(settings.currentTheme()))
            return QColor();
    }

    if(m_theme.contains(name))
        return QColor(m_theme[name].toString());

    return QColor();
}

QIcon ThemeProvider::icon(const QString &name)
{
    REDasmSettings settings;

    return QIcon(QString(":/res/%1/%2.png").arg(ThemeProvider::isDarkTheme() ? "dark" : "light")
                                           .arg(name));
}

QColor ThemeProvider::seekColor() { return ThemeProvider::themeValue("seek"); }
QColor ThemeProvider::dottedColor() { return ThemeProvider::themeValue("meta_fg"); }

void ThemeProvider::styleCornerButton(QTableView* tableview)
{
    tableview->setStyleSheet(QString("QTableCornerButton::section { border-width: 1px; border-color: %1; border-style:solid; }")
                             .arg(qApp->palette().color(QPalette::Shadow).name()));
}

void ThemeProvider::applyTheme()
{
    REDasmSettings settings;

    if(!ThemeProvider::loadTheme(settings.currentTheme()))
        return;

    QPalette palette = qApp->palette();

    THEME_UI_SET_COLOR(palette, Shadow);
    THEME_UI_SET_COLOR(palette, Base);
    THEME_UI_SET_COLOR(palette, AlternateBase);
    THEME_UI_SET_COLOR(palette, Text);
    THEME_UI_SET_COLOR(palette, Window);
    THEME_UI_SET_COLOR(palette, WindowText);
    THEME_UI_SET_COLOR(palette, Button);
    THEME_UI_SET_COLOR(palette, ButtonText);
    THEME_UI_SET_COLOR(palette, Highlight);
    THEME_UI_SET_COLOR(palette, HighlightedText);
    THEME_UI_SET_COLOR(palette, ToolTipBase);
    THEME_UI_SET_COLOR(palette, ToolTipText);

    qApp->setPalette(palette);
}

QStringList ThemeProvider::readThemes(const QString &path)
{
    QStringList themes = QDir(path).entryList({"*.json"});

    for(QString& theme : themes)
    {
        theme.remove(".json");
        theme[0] = theme[0].toUpper();
    }

    return themes;
}
