#pragma once

#include <QList>
#include "disassemblermodel.h"
#include <rdapi/document/document.h>
#include <rdapi/events.h>

class ListingItemModel : public DisassemblerModel
{
    Q_OBJECT

    public:
        explicit ListingItemModel(type_t itemtype, QObject *parent = nullptr);
        virtual ~ListingItemModel();
        void setDisassembler(RDDisassembler* disassembler) override;
        const RDDocumentItem& item(const QModelIndex& index) const;

    public:
        int rowCount(const QModelIndex& = QModelIndex()) const override;
        int columnCount(const QModelIndex& = QModelIndex()) const override;
        QVariant headerData(int section, Qt::Orientation orientation, int role) const override;
        QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const override;

    protected:
        virtual bool isItemAllowed(const RDDocumentItem& item) const;
        virtual void onItemChanged(const RDDocumentEventArgs* e);
        virtual void onItemRemoved(const RDDocumentEventArgs* e);
        virtual void insertItem(const RDDocumentItem& item);

    private:
        static QString escapeString(const QString& s);

    private:
        QList<RDDocumentItem> m_items;
        type_t m_itemtype;

    friend class ListingFilterModel;
};
