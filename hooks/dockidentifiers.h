#pragma once

#include <QWidget>
#include <QString>
#include <unordered_map>
#include <stack>

class DockIdentifiers
{
    public:
        DockIdentifiers() = delete;
        static QString getId(QWidget* w);

    private:
        static QString makeId(const QString& id, size_t idx);

    private:
        static std::unordered_multimap<QString, size_t> m_freeids;
        static std::unordered_map<QString, size_t> m_ids;
};

