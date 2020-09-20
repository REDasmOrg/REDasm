#include "listingfiltermodel.h"

ListingFilterModel::ListingFilterModel(QObject *parent) : QSortFilterProxyModel(parent) { }
const RDDocumentItem& ListingFilterModel::item(const QModelIndex &index) const { return static_cast<ListingItemModel*>(this->sourceModel())->item(this->mapToSource(index));  }
void ListingFilterModel::setDisassembler(const RDDisassemblerPtr& disassembler) { static_cast<ListingItemModel*>(this->sourceModel())->setDisassembler(disassembler); }
