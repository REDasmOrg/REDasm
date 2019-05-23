#ifndef CALLTREEMODEL_H
#define CALLTREEMODEL_H

#include <QAbstractItemModel>
#include <QHash>
#include <core/disassembler/disassemblerapi.h>
#include <core/plugins/assembler/printer.h>
#include <core/disassembler/listing/listingdocument.h>

class CallTreeModel : public QAbstractItemModel
{
    Q_OBJECT

    public:
        explicit CallTreeModel(QObject *parent = nullptr);
        void setDisassembler(const REDasm::DisassemblerPtr& disassembler);
        void initializeGraph(address_t address);
        void clearGraph();

    public slots:
        void populateCallGraph(const QModelIndex& index);

    private:
        void populate(REDasm::ListingItem *parentitem);
        bool isDuplicate(const QModelIndex& index) const;
        int getParentIndexFromChild(REDasm::ListingItem *childitem) const;
        int getParentIndex(REDasm::ListingItem *parentitem) const;

    public:
        address_location getCallTarget(const REDasm::ListingItem *item) const;
        bool hasChildren(const QModelIndex& parentindex) const override;
        QModelIndex index(int row, int column, const QModelIndex &parent) const override;
        QModelIndex parent(const QModelIndex &child) const override;
        QVariant headerData(int section, Qt::Orientation orientation, int role) const override;
        QVariant data(const QModelIndex &index, int role) const override;
        int columnCount(const QModelIndex& parent) const override;
        int rowCount(const QModelIndex& parent) const override;

    private:
        REDasm::PrinterPtr m_printer;
        REDasm::DisassemblerPtr m_disassembler;
        REDasm::ListingItem* m_root;
        QHash<REDasm::ListingItem*, s32> m_depths;
        QHash<REDasm::ListingItem*, REDasm::ListingItems> m_children;
        QHash<REDasm::ListingItem*, REDasm::ListingItem*> m_parents;
};

#endif // CALLTREEMODEL_H
