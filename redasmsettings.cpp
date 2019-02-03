#include "redasmsettings.h"

QByteArray REDasmSettings::m_defaultstate;

REDasmSettings::REDasmSettings(QObject *parent) : QSettings(parent) { }

bool REDasmSettings::restoreState(QMainWindow *mainwindow)
{
    m_defaultstate = mainwindow->saveState(); // Keep default state

    if(this->contains("window_state"))
        mainwindow->restoreState(this->value("window_state").toByteArray());

    if(this->contains("window_geometry"))
    {
        mainwindow->restoreGeometry(this->value("window_geometry").toByteArray());
        return true;
    }

    return false;
}

void REDasmSettings::defaultState(QMainWindow *mainwindow) { mainwindow->restoreState(m_defaultstate); }

void REDasmSettings::saveState(const QMainWindow *mainwindow)
{
    this->setValue("window_state", mainwindow->saveState());
    this->setValue("window_geometry", mainwindow->saveGeometry());
}

QStringList REDasmSettings::recentFiles() const { return this->value("recent_files").toStringList(); }

void REDasmSettings::updateRecentFiles(const QString &s)
{
    QStringList recents = this->recentFiles();
    recents.removeAll(s); // Remove duplicates
    recents.prepend(s);

    while(recents.length() > MAX_RECENT_FILES)
        recents.removeLast();

    this->setValue("recent_files", recents);
}

QString REDasmSettings::currentTheme() const { return this->value("selected_theme", "light").toString(); }
void REDasmSettings::changeTheme(const QString& theme) { this->setValue("selected_theme", theme.toLower()); }
