#include "dockidentifiers.h"
#include <QRegularExpression>

std::unordered_map<QWidget*, size_t> DockIdentifiers::m_lockedids;
std::unordered_multimap<QString, size_t> DockIdentifiers::m_freeids;
std::unordered_map<QString, size_t> DockIdentifiers::m_ids;

QString DockIdentifiers::getId(QWidget* w)
{
    auto title = w->windowTitle();
    if(title.isEmpty()) return QString();

    QObject::connect(w, &QWidget::destroyed, &DockIdentifiers::freeId);

    auto it = m_freeids.find(title);
    size_t idval;
    QString id;

    if(it == m_freeids.end())
    {
        idval = ++m_ids[title];
        id = title;
    }
    else
    {
        idval = it->second;
        id = DockIdentifiers::makeId(title, it->second);
        m_freeids.erase(it);
    }

    m_lockedids[w] = idval;
    return id;
}

void DockIdentifiers::freeId(QObject* obj)
{
    QWidget* w = dynamic_cast<QWidget*>(obj);
    if(!w) return;

    auto it = m_lockedids.find(w);
    if(it == m_lockedids.end()) return;

    m_freeids.insert({w->windowTitle(), it->second});
    m_lockedids.erase(it);
}

QString DockIdentifiers::makeId(const QString& id, size_t idx)
{
    return QString("%1-%2").arg(id.toLower().replace(QRegularExpression("[ \t\n\r]"), "_")).arg(idx);
}
