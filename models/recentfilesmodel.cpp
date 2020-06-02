#include "recentfilesmodel.h"
#include "../redasmsettings.h"
#include <QFileInfo>

RecentFilesModel::RecentFilesModel(QObject *parent) : QAbstractListModel(parent) { }
const QString& RecentFilesModel::filePath(const QModelIndex& index) const { return m_recents[index.row()]; }

void RecentFilesModel::update()
{
    this->beginResetModel();

    REDasmSettings settings;
    m_recents = settings.recentFiles();

    for(auto it = m_recents.begin(); it != m_recents.end(); )
    {
        if(!QFileInfo::exists(*it)) it = m_recents.erase(it);
        else it++;
    }

    this->endResetModel();
}

int RecentFilesModel::rowCount(const QModelIndex&) const { return m_recents.size(); }
int RecentFilesModel::columnCount(const QModelIndex&) const { return 1; }

QVariant RecentFilesModel::data(const QModelIndex& index, int role) const
{
    if(role == Qt::UserRole) return m_recents[index.row()];
    return QVariant();
}
