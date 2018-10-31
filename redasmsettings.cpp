#include "redasmsettings.h"

REDasmSettings::REDasmSettings(QObject *parent) : QSettings(parent) { }
bool REDasmSettings::isDarkTheme() const { return this->value("theme") == Theme::Dark; }
int REDasmSettings::currentTheme() const { return this->value("theme", 0).toInt(); }
void REDasmSettings::changeTheme(int theme) { this->setValue("theme", theme); }
