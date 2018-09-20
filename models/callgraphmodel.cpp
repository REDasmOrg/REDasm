#include "callgraphmodel.h"
#include "../../redasm/plugins/format.h"
#include <QFontDatabase>
#include <QColor>

CallGraphModel::CallGraphModel(QObject *parent) : QAbstractItemModel(parent), m_disassembler(NULL), m_root(NULL) { }

void CallGraphModel::setDisassembler(REDasm::DisassemblerAPI *disassembler)
{
    m_disassembler = disassembler;
    m_printer = REDasm::PrinterPtr(m_disassembler->assembler()->createPrinter(m_disassembler));
}

void CallGraphModel::initializeGraph(address_t address)
{
    this->beginResetModel();
    m_root = NULL;
    m_children.clear();
    m_parents.clear();
    this->endResetModel();

    REDasm::ListingDocument* doc = m_disassembler->document();
    auto it = doc->functionItem(address);

    if(it != doc->end())
    {
        m_root = it->get();
        m_parents[m_root] = NULL;
        this->populate(m_root);
    }
}

void CallGraphModel::populateCallGraph(const QModelIndex &index) { this->populate(reinterpret_cast<REDasm::ListingItem*>(index.internalPointer())); }

void CallGraphModel::populate(REDasm::ListingItem* parentitem)
{
    if(m_children.contains(parentitem))
        return;

    REDasm::ListingDocument* doc = m_disassembler->document();
    REDasm::ListingItems calls = doc->getCalls(parentitem);
    QModelIndex index = parentitem == m_root ? QModelIndex() : this->createIndex(this->getParentIndex(parentitem), 0, parentitem);

    this->beginInsertRows(index, 0, calls.size());
    m_children[parentitem] = calls;

    for(REDasm::ListingItem* item : m_children[parentitem])
        m_parents[item] = parentitem;

    this->endInsertRows();
}

int CallGraphModel::getParentIndexFromChild(REDasm::ListingItem *childitem) const
{
    if(childitem == m_root)
        return -1;

    REDasm::ListingItem* parentitem = m_parents[childitem];
    return this->getParentIndex(parentitem);
}

int CallGraphModel::getParentIndex(REDasm::ListingItem *parentitem) const
{
    const REDasm::ListingItems& parentlist = m_children[m_parents[parentitem]];
    return REDasm::Listing::indexOf(&parentlist, parentitem);
}

bool CallGraphModel::hasChildren(const QModelIndex &parentindex) const
{
    if(!m_disassembler || !m_root || m_children.empty())
        return false;

    REDasm::ListingItem* parentitem = reinterpret_cast<REDasm::ListingItem*>(parentindex.internalPointer());

    if(m_children.contains(parentitem))
    {
        const REDasm::ListingItems& children = m_children[parentitem];

        if(children.empty())
            return false;
    }

    return true;
}

QModelIndex CallGraphModel::index(int row, int column, const QModelIndex &parent) const
{
    if(!m_disassembler || !m_root || m_children.empty())
        return QModelIndex();

    REDasm::ListingItem* parentitem = reinterpret_cast<REDasm::ListingItem*>(parent.internalPointer());

    if(!parentitem)
        return this->createIndex(row, column, m_root);

    return this->createIndex(row, column, m_children[parentitem][row]);
}

QModelIndex CallGraphModel::parent(const QModelIndex &child) const
{
    if(!m_disassembler || !m_root)
        return QModelIndex();

    REDasm::ListingItem* childitem = reinterpret_cast<REDasm::ListingItem*>(child.internalPointer());

    if(childitem == m_root)
        return QModelIndex();

    REDasm::ListingItem* parentitem = m_parents[childitem];
    return this->createIndex(this->getParentIndexFromChild(childitem), 0, parentitem);
}

QVariant CallGraphModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if(orientation != Qt::Horizontal)
        return QVariant();

    if(role == Qt::DisplayRole)
    {
        if(section == 0)
            return "Address";

        if(section == 1)
            return "Value";

        if(section == 2)
            return "R";
    }
    else if(role == Qt::TextAlignmentRole)
        return Qt::AlignCenter;

    return QVariant();
}

QVariant CallGraphModel::data(const QModelIndex &index, int role) const
{
    if(!m_disassembler || !m_root)
        return QVariant();

    REDasm::ListingItem* item = reinterpret_cast<REDasm::ListingItem*>(index.internalPointer());

    if(role == Qt::DisplayRole)
    {
        if(index.column() == 0)
            return QString::fromStdString(REDasm::hex(item->address, m_disassembler->format()->bits(), false));
        else if(index.column() == 1)
        {
            if(item->is(REDasm::ListingItem::FunctionItem))
            {
                REDasm::SymbolPtr symbol = m_disassembler->document()->symbol(item->address);
                return QString::fromStdString(symbol->name);
            }

            return QString::fromStdString(m_printer->out(m_disassembler->document()->instruction(item->address)));
        }
        else if(index.column() == 2)
            return item == m_root ? "---" : QString::number(m_disassembler->getReferencesCount(item->address));
    }
    else if((role == Qt::ForegroundRole) && (index.column() == 0))
        return QColor(Qt::darkBlue);
    else if((role == Qt::TextAlignmentRole) && (index.column() == 2))
        return Qt::AlignCenter;

    return QVariant();
}

int CallGraphModel::columnCount(const QModelIndex &parent) const { Q_UNUSED(parent) return 3; }

int CallGraphModel::rowCount(const QModelIndex &parent) const
{
    if(!m_disassembler || !m_root || m_children.empty())
        return 0;

    REDasm::ListingItem* parentitem = reinterpret_cast<REDasm::ListingItem*>(parent.internalPointer());

    if(!parentitem)
        return 1;

    return m_children[parentitem].size();
}
