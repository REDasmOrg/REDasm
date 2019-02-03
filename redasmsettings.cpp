#include "redasmsettings.h"

REDasmSettings::REDasmSettings(QObject *parent) : QSettings(parent) { }
bool REDasmSettings::hasGeometry() const { return this->contains("geometry"); }
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

QByteArray REDasmSettings::geometry() const { return this->value("geometry").toByteArray(); }
QString REDasmSettings::currentTheme() const { return this->value("selected_theme", "light").toString(); }
void REDasmSettings::changeGeometry(const QByteArray &ba) { this->setValue("geometry", ba); }
void REDasmSettings::changeTheme(const QString& theme) { this->setValue("selected_theme", theme.toLower()); }
