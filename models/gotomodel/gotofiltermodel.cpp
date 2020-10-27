#include "gotofiltermodel.h"
#include <rdapi/rdapi.h>

GotoFilterModel::GotoFilterModel(QObject *parent) : QSortFilterProxyModel(parent)
{
    this->setFilterKeyColumn(-1);
    this->setFilterCaseSensitivity(Qt::CaseInsensitive);
    this->setSourceModel(new GotoModel(this));
}

void GotoFilterModel::setContext(const RDContextPtr& ctx) { static_cast<GotoModel*>(this->sourceModel())->setContext(ctx); }

bool GotoFilterModel::filterAcceptsRow(int sourcerow, const QModelIndex &sourceparent) const
{
    auto* gotomodel = static_cast<const GotoModel*>(this->sourceModel());
    const RDDocumentItem& item = gotomodel->item(sourcerow);

    switch(item.type)
    {
        case DocumentItemType_Segment:
        case DocumentItemType_Function:
        case DocumentItemType_Symbol:
        case DocumentItemType_Type:
            return QSortFilterProxyModel::filterAcceptsRow(sourcerow, sourceparent);

        default: break;
    }

    return false;
}
