#pragma once

#include <QWidget>
#include <QString>
#include <QMultiHash>
#include <QHash>

class DockIdentifiers
{
    public:
        DockIdentifiers() = delete;
        static QString getId(QWidget* w);

    private Q_SLOTS:
        static void freeId(QObject* obj);

    private:
        static QString makeId(const QString& id, size_t idx);

    private:
        static QMultiHash<QString, size_t> m_freeids;
        static QHash<QWidget*, size_t> m_lockedids;
        static QHash<QString, size_t> m_ids;
};

