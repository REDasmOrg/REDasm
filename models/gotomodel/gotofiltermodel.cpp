#include "gotofiltermodel.h"
#include <redasm/disassembler/listing/document/listingdocument.h>

GotoFilterModel::GotoFilterModel(QObject *parent) : QSortFilterProxyModel(parent)
{
    this->setFilterKeyColumn(-1);
    this->setFilterCaseSensitivity(Qt::CaseInsensitive);
    this->setSourceModel(new GotoModel(this));
}

void GotoFilterModel::setDisassembler(RDDisassembler* disassembler) { static_cast<GotoModel*>(this->sourceModel())->setDisassembler(disassembler); }

bool GotoFilterModel::filterAcceptsRow(int sourcerow, const QModelIndex &sourceparent) const
{
    // const GotoModel* gotomodel = static_cast<const GotoModel*>(this->sourceModel());
    // REDasm::ListingItem item = gotomodel->disassembler()->document()->items()->at(sourcerow);
    // if(!item.isValid()) return false;

    // switch(item.type)
    // {
    //     case REDasm::ListingItem::SegmentItem:
    //     case REDasm::ListingItem::FunctionItem:
    //     case REDasm::ListingItem::SymbolItem:
    //     case REDasm::ListingItem::TypeItem:
    //         return QSortFilterProxyModel::filterAcceptsRow(sourcerow, sourceparent);

    //     default: break;
    // }

    return false;
}
