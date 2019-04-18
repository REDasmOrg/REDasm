#ifndef REDASMSETTINGS_H
#define REDASMSETTINGS_H

#define MAX_RECENT_FILES 10

#include <QSettings>
#include <QMainWindow>

class REDasmSettings : public QSettings
{
    Q_OBJECT

    public:
        explicit REDasmSettings(QObject *parent = NULL);
        QStringList recentFiles() const;
        QString currentTheme() const;
        QFont currentFont() const;
        int currentFontSize() const;
        bool restoreState(QMainWindow* mainwindow);
        void defaultState(QMainWindow* mainwindow);
        void saveState(const QMainWindow* mainwindow);
        void updateRecentFiles(const QString& s = QString());
        void changeTheme(const QString& theme);
        void changeFont(const QFont &font);
        void changeFontSize(int size);

    public:
        static QFont font();

    private:
        static QByteArray m_defaultstate;
};

#endif // REDASMSETTINGS_H
