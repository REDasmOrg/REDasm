#include "redasmsettings.h"

REDasmSettings::REDasmSettings(QObject *parent) : QSettings(parent) { }
bool REDasmSettings::isDarkTheme() const { return this->value("theme") == Theme::Dark; }
void REDasmSettings::changeTheme(int theme) { this->setValue("theme", theme); }
