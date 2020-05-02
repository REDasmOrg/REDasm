#pragma once

#include <QAbstractListModel>
//#include <redasm/database/signaturedb.h>

class SignaturesModel : public QAbstractListModel
{
    Q_OBJECT

    public:
        explicit SignaturesModel(QObject *parent = nullptr);
        //void setSignature(const REDasm::SignatureDB* sigdb);

    public:
        QVariant data(const QModelIndex &index, int role) const override;
        QVariant headerData(int section, Qt::Orientation orientation, int role) const override;
        int rowCount(const QModelIndex& = QModelIndex()) const override;
        int columnCount(const QModelIndex& = QModelIndex()) const override;

    private:
        //const REDasm::SignatureDB* m_signaturedb;
};
