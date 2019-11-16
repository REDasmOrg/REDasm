#include "gotofiltermodel.h"
#include <redasm/disassembler/listing/document/listingdocumentnew.h>

GotoFilterModel::GotoFilterModel(QObject *parent) : QSortFilterProxyModel(parent)
{
    this->setFilterKeyColumn(-1);
    this->setFilterCaseSensitivity(Qt::CaseInsensitive);
    this->setSourceModel(new GotoModel(this));
}

void GotoFilterModel::setDisassembler(const REDasm::DisassemblerPtr &disassembler) { static_cast<GotoModel*>(this->sourceModel())->setDisassembler(disassembler); }

bool GotoFilterModel::filterAcceptsRow(int sourcerow, const QModelIndex &sourceparent) const
{
    const GotoModel* gotomodel = static_cast<const GotoModel*>(this->sourceModel());
    REDasm::ListingItem item = gotomodel->disassembler()->documentNew()->items()->at(sourcerow);

    if(!item.isValid())
        return false;

    switch(item.type_new)
    {
        case REDasm::ListingItemType::SegmentItem:
        case REDasm::ListingItemType::FunctionItem:
        case REDasm::ListingItemType::SymbolItem:
        case REDasm::ListingItemType::TypeItem:
            return QSortFilterProxyModel::filterAcceptsRow(sourcerow, sourceparent);

        default: break;
    }

    return false;
}
