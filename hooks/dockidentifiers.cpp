#include "dockidentifiers.h"

std::unordered_multimap<QString, size_t> DockIdentifiers::m_freeids;
std::unordered_map<QString, size_t> DockIdentifiers::m_ids;

QString DockIdentifiers::getId(QWidget* w)
{
    auto title = w->windowTitle();
    if(title.isEmpty()) return QString();

    auto it = m_freeids.find(title);
    QString id;

    if(it == m_freeids.end())
    {
        id = title;
        m_ids[title]++;
    }
    else
    {
        id = DockIdentifiers::makeId(title, it->second);
        m_freeids.erase(it);
    }

    return id;
}

QString DockIdentifiers::makeId(const QString& id, size_t idx) { return QString("%1-%2").arg(id).arg(idx); }
