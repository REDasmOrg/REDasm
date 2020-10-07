#pragma once

#include <QAbstractListModel>
#include <rdapi/rdapi.h>
#include "../hooks/icommand.h"

class SignatureFilesModel : public QAbstractListModel
{
    Q_OBJECT

    public:
        explicit SignatureFilesModel(const RDContextPtr& ctx, QObject *parent = nullptr);
        //const REDasm::SignatureDB* load(const QModelIndex& index);
        //const REDasm::String& signatureId(const QModelIndex& index) const;
        //const REDasm::String& signaturePath(const QModelIndex& index) const;
        //bool isLoaded(const QModelIndex& index) const;
        //bool contains(const REDasm::String& sigid) const;
        //void add(const REDasm::String& sigid, const REDasm::String& sigpath);
        //void mark(const QModelIndex& index);

    public:
        QVariant data(const QModelIndex &index, int role) const override;
        QVariant headerData(int section, Qt::Orientation orientation, int role) const override;
        int rowCount(const QModelIndex& = QModelIndex()) const override;
        int columnCount(const QModelIndex& = QModelIndex()) const override;

    private:
        //QList< QPair<REDasm::String, REDasm::String> > m_signaturefiles;
        //QHash<int, REDasm::SignatureDB> m_loadedsignatures;
        RDContextPtr m_context;
};
