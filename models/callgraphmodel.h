#ifndef CALLGRAPHMODEL_H
#define CALLGRAPHMODEL_H

#include <QAbstractItemModel>
#include <QHash>
#include <redasm/disassembler/disassemblerapi.h>
#include <redasm/plugins/assembler/printer.h>
#include <redasm/disassembler/listing/listingdocument.h>

class CallGraphModel : public QAbstractItemModel
{
    Q_OBJECT

    public:
        explicit CallGraphModel(QObject *parent = nullptr);
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
        virtual bool hasChildren(const QModelIndex& parentindex) const;
        virtual QModelIndex index(int row, int column, const QModelIndex &parent) const;
        virtual QModelIndex parent(const QModelIndex &child) const;
        virtual QVariant headerData(int section, Qt::Orientation orientation, int role) const;
        virtual QVariant data(const QModelIndex &index, int role) const;
        virtual int columnCount(const QModelIndex& parent) const;
        virtual int rowCount(const QModelIndex& parent) const;

    private:
        REDasm::PrinterPtr m_printer;
        REDasm::DisassemblerPtr m_disassembler;
        REDasm::ListingItem* m_root;
        QHash<REDasm::ListingItem*, s32> m_depths;
        QHash<REDasm::ListingItem*, REDasm::ListingItems> m_children;
        QHash<REDasm::ListingItem*, REDasm::ListingItem*> m_parents;
};

#endif // CALLGRAPHMODEL_H
