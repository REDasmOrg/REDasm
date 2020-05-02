#pragma once

#include <QAbstractListModel>
#include <QStringList>

class RecentFilesModel : public QAbstractListModel
{
    Q_OBJECT

    public:
        explicit RecentFilesModel(QObject *parent = nullptr);
        const QString& filePath(const QModelIndex& index) const;
        void update();

    public:
        int rowCount(const QModelIndex& = QModelIndex()) const override;
        int columnCount(const QModelIndex& = QModelIndex()) const override;
        QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const override;

    private:
        QStringList m_recents;
};

