#include "gotofiltermodel.h"
#include <rdapi/rdapi.h>

GotoFilterModel::GotoFilterModel(QObject *parent) : QSortFilterProxyModel(parent)
{
    this->setFilterKeyColumn(-1);
    this->setFilterCaseSensitivity(Qt::CaseInsensitive);
    this->setSourceModel(new GotoModel(this));
}

void GotoFilterModel::setDisassembler(const RDContextPtr& disassembler) { static_cast<GotoModel*>(this->sourceModel())->setContext(disassembler); }

bool GotoFilterModel::filterAcceptsRow(int sourcerow, const QModelIndex &sourceparent) const
{
    const GotoModel* gotomodel = static_cast<const GotoModel*>(this->sourceModel());
    RDDocument* doc = RDContext_GetDocument(gotomodel->context().get());

    RDDocumentItem item;
    if(!RDDocument_GetItemAt(doc, sourcerow, &item)) return false;

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
