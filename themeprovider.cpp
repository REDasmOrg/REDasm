#include "themeprovider.h"
#include <QJsonDocument>
#include <QVariant>
#include <QFile>

QJsonObject ThemeProvider::_theme;

ThemeProvider::ThemeProvider()
{

}

void ThemeProvider::loadTheme(const QString& theme)
{
    if(!_theme.isEmpty())
        return;

    QFile f(QString(":/themes/disassembler/%1.json").arg(theme));

    if(!f.open(QFile::ReadOnly))
    {
        qWarning("Cannot load '%s' theme", qUtf8Printable(theme));
        return;
    }

    QJsonDocument doc = QJsonDocument::fromJson(f.readAll());

    if(doc.isObject())
        _theme = doc.object();

    f.close();
}

QColor ThemeProvider::themeValue(const QString &name)
{
    ThemeProvider::loadTheme("light");

    if(_theme.contains(name))
        return QColor(_theme[name].toString());

    return QColor();
}

QColor ThemeProvider::highlightColor()
{
    return ThemeProvider::themeValue("highlight");
}

QColor ThemeProvider::seekColor()
{
    return ThemeProvider::themeValue("seek");
}

QColor ThemeProvider::dottedColor()
{
    return ThemeProvider::themeValue("dotted_fg");
}
