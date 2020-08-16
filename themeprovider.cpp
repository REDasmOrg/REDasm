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
    if(!m_theme.isEmpty()) return true;

    QFile f(QString(":/themes/%1.json").arg(theme.toLower()));
    if(!f.open(QFile::ReadOnly)) return false;

    QJsonDocument doc = QJsonDocument::fromJson(f.readAll());
    if(doc.isObject()) m_theme = doc.object();
    else return false;

    return true;
}

QColor ThemeProvider::themeValue(rd_type theme)
{
    auto* c = RDTheme_Get(theme);
    return c ? QColor(c) : QColor();
}

QIcon ThemeProvider::icon(const QString &name)
{
    REDasmSettings settings;

    return QIcon(QString(":/res/%1/%2.png").arg(ThemeProvider::isDarkTheme() ? "dark" : "light")
                                           .arg(name));
}

QColor ThemeProvider::seekColor() { return ThemeProvider::themeValue(Theme_Seek); }
QColor ThemeProvider::metaColor() { return ThemeProvider::themeValue(Theme_Meta); }

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
    ThemeProvider::applyListingTheme();
}

void ThemeProvider::applyListingTheme()
{
    static std::unordered_map<std::string, rd_type> themes = {
        { "foreground", Theme_Foreground },
        { "background", Theme_Background },
        { "seek", Theme_Seek },
        { "comment", Theme_Comment },
        { "meta", Theme_Meta },
        { "highlight_fg", Theme_HighlightFg },
        { "highlight_bg", Theme_HighlightBg },
        { "selection_fg", Theme_SelectionFg },
        { "selection_bg", Theme_SelectionBg },
        { "cursor_fg", Theme_CursorFg },
        { "cursor_bg", Theme_CursorBg },
        { "segment", Theme_Segment },
        { "function", Theme_Function },
        { "address", Theme_Address },
        { "constant", Theme_Constant },
        { "reg", Theme_Reg },
        { "string", Theme_String },
        { "symbol", Theme_Symbol },
        { "data", Theme_Data },
        { "pointer", Theme_Pointer },
        { "import", Theme_Imported },
        { "nop", Theme_Nop },
        { "ret", Theme_Ret },
        { "call", Theme_Call },
        { "jump", Theme_Jump },
        { "jump_c", Theme_JumpCond },
        { "graph_bg", Theme_GraphBg },
        { "graph_edge", Theme_GraphEdge },
        { "graph_edge_true", Theme_GraphEdgeTrue },
        { "graph_edge_false", Theme_GraphEdgeFalse },
        { "graph_edge_loop", Theme_GraphEdgeLoop },
        { "graph_edge_loop_c", Theme_GraphEdgeLoopCond } };

    for(auto it = m_theme.begin(); it != m_theme.end(); it++)
    {
        auto thit = themes.find(it.key().toStdString());
        if(thit == themes.end()) continue;
        RDTheme_Set(thit->second, it.value().toString().toStdString().c_str());
    }
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
