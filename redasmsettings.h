#ifndef REDASMSETTINGS_H
#define REDASMSETTINGS_H

#include <QSettings>

class REDasmSettings : public QSettings
{
    Q_OBJECT

    public:
        enum Theme { Light = 0, Dark };

    public:
        explicit REDasmSettings(QObject *parent = NULL);
        bool isDarkTheme() const;
        void changeTheme(int theme);
};

#endif // REDASMSETTINGS_H
