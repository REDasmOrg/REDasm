#ifndef REDASMSETTINGS_H
#define REDASMSETTINGS_H

#define MAX_RECENT_FILES 5

#include <QSettings>

class REDasmSettings : public QSettings
{
    Q_OBJECT

    public:
        explicit REDasmSettings(QObject *parent = NULL);
        QStringList recentFiles() const;
        QByteArray geometry() const;
        QString currentTheme() const;
        bool hasGeometry() const;
        void updateRecentFiles(const QString& s = QString());
        void changeGeometry(const QByteArray& ba);
        void changeTheme(const QString& theme);
};

#endif // REDASMSETTINGS_H
