#include "listingdocumentmodel.h"
#include "../../redasm/plugins/format.h"
#include <QColor>

ListingDocumentModel::ListingDocumentModel(QObject *parent) : DisassemblerModel(parent)
{

}

void ListingDocumentModel::setDisassembler(REDasm::DisassemblerAPI *disassembler)
{
    this->beginResetModel();

    DisassemblerModel::setDisassembler(disassembler);
    m_disassembler->document()->whenChanged(std::bind(&ListingDocumentModel::onListingChanged, this, std::placeholders::_1));

    this->endResetModel();
}

QModelIndex ListingDocumentModel::index(int row, int column, const QModelIndex &) const
{
    REDasm::ListingItem* item = m_disassembler->document()->itemAt(row);
    return this->createIndex(row, column, item);
}

QVariant ListingDocumentModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if(orientation == Qt::Vertical)
        return QVariant();

    if(role == Qt::DisplayRole)
    {
        if(section == 0)
            return "Address";
        else if(section == 1)
            return "Symbol";
        else if(section == 2)
            return "R";
        else if(section == 3)
            return "Segment";
    }

    return DisassemblerModel::headerData(section, orientation, role);
}

QVariant ListingDocumentModel::data(const QModelIndex &index, int role) const
{
    REDasm::ListingItem* item = reinterpret_cast<REDasm::ListingItem*>(index.internalPointer());

    if(!item || (!item->is(REDasm::ListingItem::FunctionItem) && !item->is(REDasm::ListingItem::SymbolItem)))
        return DisassemblerModel::data(index, role);

    REDasm::SymbolPtr symbol = m_disassembler->document()->symbol(item->address);

    if(!symbol)
        return DisassemblerModel::data(index, role);

    if(role == Qt::DisplayRole)
    {
        if(index.column() == 0)
            return S_TO_QS(REDasm::hex(symbol->address, m_disassembler->format()->bits(), false));

        if(index.column() == 1)
        {
            if(symbol->is(REDasm::SymbolTypes::WideStringMask))
                return S_TO_QS(REDasm::quoted(m_disassembler->readWString(symbol)));
            else if(symbol->is(REDasm::SymbolTypes::StringMask))
                return S_TO_QS(REDasm::quoted(m_disassembler->readString(symbol)));

            return S_TO_QS(symbol->name);
        }

        if(index.column() == 2)
            return QString::number(m_disassembler->getReferencesCount(symbol->address));

        if(index.column() == 3)
        {
            REDasm::Segment* segment = m_disassembler->document()->segment(symbol->address);

            if(segment)
                return S_TO_QS(segment->name);

            return "???";
        }
    }
    else if(role == Qt::BackgroundRole)
    {
        if(symbol->isFunction() && symbol->isLocked())
            return QColor::fromRgb(0xE2, 0xFF, 0xFF);
    }
    else if(role == Qt::ForegroundRole)
    {
        if((index.column() == 0) || (index.column() == 2))
            return QColor(Qt::darkBlue);

        if(symbol->is(REDasm::SymbolTypes::String) && (index.column() == 1))
            return QColor(Qt::darkGreen);
    }

    return DisassemblerModel::data(index, role);
}

int ListingDocumentModel::columnCount(const QModelIndex &) const { return 4; }

int ListingDocumentModel::rowCount(const QModelIndex&) const
{
    if(!m_disassembler)
        return 0;

    return m_disassembler->document()->size();
}

void ListingDocumentModel::onListingChanged(const REDasm::ListingDocumentChanged *ldc)
{
    if(ldc->removed)
    {
        this->beginRemoveRows(QModelIndex(), ldc->index, ldc->index);
        this->endRemoveRows();
        return;
    }

    this->beginInsertRows(QModelIndex(), ldc->index, ldc->index);
    this->endInsertRows();
}

