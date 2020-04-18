#pragma once

#include <QList>
#include <QSet>
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
        //address_location address(const QModelIndex& index) const;

    public:
        int rowCount(const QModelIndex& = QModelIndex()) const override;
        int columnCount(const QModelIndex& = QModelIndex()) const override;
        QVariant headerData(int section, Qt::Orientation orientation, int role) const override;
        QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const override;

    protected:
        virtual bool isItemAllowed(const RDDocumentItem& item) const;

    private:
        static QString escapeString(const QString& s);
        void onItemChanged(const RDEventArgs* e);
        void onItemInserted(const RDEventArgs* e);
        void onItemRemoved(const RDEventArgs* e);

    protected:
        RDDocument* m_document{nullptr};

    private:
        QList<RDDocumentItem> m_items;
        QSet<event_t> m_events;
        type_t m_itemtype;

    friend class ListingFilterModel;
};
