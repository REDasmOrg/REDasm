#ifndef REDASMSETTINGS_H
#define REDASMSETTINGS_H

#define MAX_RECENT_FILES 5

#include <QSettings>

class REDasmSettings : public QSettings
{
    Q_OBJECT

    public:
        enum Theme { Light = 0, Dark };

    public:
        explicit REDasmSettings(QObject *parent = NULL);
        bool hasGeometry() const;
        QStringList recentFiles() const;
        void updateRecentFiles(const QString& s = QString());
        QByteArray geometry() const;
        void changeGeometry(const QByteArray& ba);
        bool isDarkTheme() const;
        int currentTheme() const;
        void changeTheme(int theme);
};

#endif // REDASMSETTINGS_H
