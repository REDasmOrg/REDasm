#include "themeprovider.h"
#include <QApplication>
#include <QJsonDocument>
#include <QPalette>
#include <QVariant>
#include <QFile>
#include "redasmsettings.h"

QJsonObject ThemeProvider::m_theme;

void ThemeProvider::loadTheme(const QString& theme)
{
    if(!m_theme.isEmpty())
        return;

    QFile f(QString(":/themes/disassembler/%1.json").arg(theme));

    if(!f.open(QFile::ReadOnly))
    {
        qWarning("Cannot load '%s' theme", qUtf8Printable(theme));
        return;
    }

    QJsonDocument doc = QJsonDocument::fromJson(f.readAll());

    if(doc.isObject())
        m_theme = doc.object();

    f.close();
}

QColor ThemeProvider::themeValue(const QString &name)
{
    REDasmSettings settings;

    if(settings.isDarkTheme())
        ThemeProvider::loadTheme("dark");
    else
        ThemeProvider::loadTheme("light");

    if(m_theme.contains(name))
        return QColor(m_theme[name].toString());

    return QColor();
}

QIcon ThemeProvider::icon(const QString &name)
{
    REDasmSettings settings;

    return QIcon(QString(":/res/%1/%2.png").arg(settings.isDarkTheme() ? "dark" : "light")
                                           .arg(name));
}

QColor ThemeProvider::highlightColor() { return ThemeProvider::themeValue("highlight"); }
QColor ThemeProvider::seekColor() { return ThemeProvider::themeValue("seek"); }
QColor ThemeProvider::dottedColor() { return ThemeProvider::themeValue("dotted_fg"); }

void ThemeProvider::selectDarkTheme()
{
    QPalette palette = qApp->palette();

    palette.setColor(QPalette::Shadow, "#2b2b2b");
    palette.setColor(QPalette::Base, "#262626");
    palette.setColor(QPalette::Text, "#ecf0f1");
    palette.setColor(QPalette::Window, "#2b2b2b");
    palette.setColor(QPalette::WindowText, "#ecf0f1");
    palette.setColor(QPalette::Button, "#2b2b2b");
    palette.setColor(QPalette::ButtonText, "#ecf0f1");
    palette.setColor(QPalette::Highlight, "#d95459");
    palette.setColor(QPalette::HighlightedText, "#ecf0f1");
    palette.setColor(QPalette::ToolTipBase, "#2b2b2b");
    palette.setColor(QPalette::ToolTipText, "#ecf0f1");

    qApp->setPalette(palette);
}
