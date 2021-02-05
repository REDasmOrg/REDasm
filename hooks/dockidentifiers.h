#pragma once

#include <QWidget>
#include <QString>
#include <unordered_map>

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
        static std::unordered_map<QWidget*, size_t> m_lockedids;
        static std::unordered_multimap<QString, size_t> m_freeids;
        static std::unordered_map<QString, size_t> m_ids;
};

