#ifndef SIGNATURESMODEL_H
#define SIGNATURESMODEL_H

#include <QAbstractListModel>
#include <redasm/database/signaturedb.h>

class SignaturesModel : public QAbstractListModel
{
    Q_OBJECT

    public:
        explicit SignaturesModel(QObject *parent = nullptr);
        void setSignature(const REDasm::SignatureDB* sigdb);

    public:
        virtual QVariant data(const QModelIndex &index, int role) const;
        virtual QVariant headerData(int section, Qt::Orientation orientation, int role) const;
        virtual int rowCount(const QModelIndex& = QModelIndex()) const;
        virtual int columnCount(const QModelIndex& = QModelIndex()) const;

    private:
        const REDasm::SignatureDB* m_signaturedb;
};

#endif // SIGNATURESMODEL_H
