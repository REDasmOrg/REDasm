#ifndef CALLTREEMODEL_H
#define CALLTREEMODEL_H

#include <QAbstractItemModel>
#include <QHash>
#include <redasm/disassembler/disassembler.h>
#include <redasm/plugins/assembler/printer/printer.h>
#include <redasm/disassembler/listing/listingdocument.h>

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
        void populate(const REDasm::ListingItem *parentitem);
        bool isDuplicate(const QModelIndex& index) const;
        int getParentIndexFromChild(const REDasm::ListingItem *childitem) const;
        int getParentIndex(const REDasm::ListingItem *parentitem) const;

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
        REDasm::object_ptr<REDasm::Printer> m_printer;
        REDasm::DisassemblerPtr m_disassembler;
        const REDasm::ListingItem* m_root;
        QHash<const REDasm::ListingItem*, s32> m_depths;
        QHash<const REDasm::ListingItem*, REDasm::ListingItems> m_children;
        QHash<const REDasm::ListingItem*, const REDasm::ListingItem*> m_parents;
};

#endif // CALLTREEMODEL_H
