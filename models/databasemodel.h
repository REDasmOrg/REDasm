#ifndef DATABASEMODEL_H
#define DATABASEMODEL_H

#include <QAbstractListModel>
#include "../redasm/signatures/signaturedb.h"

class DatabaseModel : public QAbstractListModel
{
    Q_OBJECT

    public:
        explicit DatabaseModel(QObject *parent = nullptr);
        void loadPats(const QStringList& patfiles);
        bool save(const QString &name, const QString& file);

    public:
        virtual QVariant data(const QModelIndex &index, int role) const;
        virtual QVariant headerData(int section, Qt::Orientation orientation, int role) const;
        virtual int rowCount(const QModelIndex& = QModelIndex()) const;
        virtual int columnCount(const QModelIndex& = QModelIndex()) const;

    private:
        REDasm::SignatureDB m_signaturedb;
};

#endif // DATABASEMODEL_H
