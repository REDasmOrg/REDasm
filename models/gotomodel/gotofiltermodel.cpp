#include "gotofiltermodel.h"

GotoFilterModel::GotoFilterModel(QObject *parent) : QSortFilterProxyModel(parent)
{
    this->setFilterKeyColumn(-1);
    this->setFilterCaseSensitivity(Qt::CaseInsensitive);
    this->setSourceModel(new GotoModel(this));
}

void GotoFilterModel::setDisassembler(const REDasm::DisassemblerPtr &disassembler) { static_cast<GotoModel*>(this->sourceModel())->setDisassembler(disassembler); }

bool GotoFilterModel::filterAcceptsRow(int sourcerow, const QModelIndex &sourceparent) const
{
    const REDasm::ListingItem* item = reinterpret_cast<const REDasm::ListingItem*>(this->sourceModel()->index(sourcerow, 0, sourceparent).internalPointer());

    if(!item)
        return false;

    switch(item->type())
    {
        case REDasm::ListingItemType::SegmentItem:
        case REDasm::ListingItemType::FunctionItem:
        case REDasm::ListingItemType::SymbolItem:
        case REDasm::ListingItemType::TypeItem:
            return QSortFilterProxyModel::filterAcceptsRow(sourcerow, sourceparent);

        default:
            break;
    }

    return false;
}
