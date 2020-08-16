#include "gotomodel.h"
#include "../../themeprovider.h"

GotoModel::GotoModel(QObject *parent) : DisassemblerModel(parent) { }

void GotoModel::setDisassembler(RDDisassembler* disassembler)
{
    this->beginResetModel();
    DisassemblerModel::setDisassembler(disassembler);
    this->endResetModel();
}

QVariant GotoModel::data(const QModelIndex &index, int role) const
{
    if(!m_disassembler) return QVariant();

    RDDocumentItem item;
    RDDocument_GetItemAt(m_document, index.row(), &item);

    if(role == Qt::DisplayRole)
    {
        if(index.column() == 0) return RD_ToHexAuto(item.address);
        if(index.column() == 1) return this->itemName(item);
        if(index.column() == 2) return this->itemType(item);
    }
    else if(role == Qt::TextAlignmentRole)
    {
        if(index.column() == 2) return Qt::AlignCenter;
    }
    else if(role == Qt::ForegroundRole)
    {
        if(index.column() == 0) return THEME_VALUE(Theme_Address);
        if(index.column() == 1) return this->itemColor(item);
    }

    return QVariant();
}

QVariant GotoModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if(orientation == Qt::Vertical)
        return QVariant();

    if(role == Qt::DisplayRole)
    {
        if(section == 0)      return "Address";
        else if(section == 1) return "Name";
        else if(section == 2) return "Type";
    }

    return DisassemblerModel::headerData(section, orientation, role);
}

int GotoModel::columnCount(const QModelIndex &) const { return 3; }
int GotoModel::rowCount(const QModelIndex &) const { return m_document ? RDDocument_ItemsCount(m_document) : 0; }

QColor GotoModel::itemColor(const RDDocumentItem& item) const
{
    RDSymbol symbol;

    switch(item.type)
    {
        case DocumentItemType_Segment:  return THEME_VALUE(Theme_Segment);
        case DocumentItemType_Function: return THEME_VALUE(Theme_Function);
        case DocumentItemType_Type:     return THEME_VALUE(Theme_Type);

        case DocumentItemType_Symbol:
            if(!RDDocument_GetSymbolByAddress(m_document, item.address, &symbol)) return QColor();
            if(IS_TYPE(&symbol, SymbolType_String)) return THEME_VALUE(Theme_String);
            return THEME_VALUE(Theme_Data);

        default: break;
    }

    return QColor();
}

QString GotoModel::itemName(const RDDocumentItem& item) const
{
    if(IS_TYPE(&item, DocumentItemType_Segment))
    {
        RDSegment segment;
        if(RDDocument_GetSegmentAddress(m_document, item.address, &segment)) return segment.name;
    }
    else if(IS_TYPE(&item, DocumentItemType_Function) || IS_TYPE(&item, DocumentItemType_Symbol))
    {
        const char* name = RDDocument_GetSymbolName(m_document, item.address);
        if(name) return RD_Demangle(name);
    }
    else if(IS_TYPE(&item, DocumentItemType_Type))
        return "TODO"; //TODO: Convert::to_qstring(r_doc->type(item.address));

    return QString();
}

QString GotoModel::itemType(const RDDocumentItem& item) const
{
    switch(item.type)
    {
        case DocumentItemType_Segment:  return "SEGMENT";
        case DocumentItemType_Function: return "FUNCTION";
        case DocumentItemType_Type:     return "TYPE";
        case DocumentItemType_Symbol:   return "SYMBOL";
        default: break;
    }

    return QString();
}
