#include "callgraphmodel.h"
#include "../../redasm/plugins/format.h"
#include "../../themeprovider.h"
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
    m_depths.clear();
    m_children.clear();
    m_parents.clear();
    this->endResetModel();

    REDasm::ListingDocument* doc = m_disassembler->document();
    auto it = doc->functionItem(address);

    if(it != doc->end())
    {
        m_root = it->get();
        m_depths[m_root] = 0;
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
    QModelIndex index;

    if(parentitem != m_root)
        index = this->createIndex(this->getParentIndex(parentitem), 0, parentitem);

    this->beginInsertRows(index, 0, calls.size());
    m_children[parentitem] = calls;

    for(REDasm::ListingItem* item : m_children[parentitem])
    {
        m_parents[item] = parentitem;

        if(!m_depths.contains(item))
            m_depths[item] = m_depths[parentitem] + 1;
    }

    this->endInsertRows();
}

bool CallGraphModel::isDuplicate(const QModelIndex &index) const
{
    REDasm::ListingItem* item = reinterpret_cast<REDasm::ListingItem*>(index.internalPointer());

    if(item == m_root)
        return false;

    QModelIndex parentindex = this->parent(index);
    REDasm::ListingItem* parentitem = reinterpret_cast<REDasm::ListingItem*>(parentindex.internalPointer());
    return (m_depths[item] - m_depths[parentitem]) != 1;
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

    if(!parentitem)
        return true;

    if(this->isDuplicate(parentindex))
        return false;

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
    REDasm::SymbolPtr symbol;

    if(item->is(REDasm::ListingItem::InstructionItem))
    {
        REDasm::InstructionPtr instruction = m_disassembler->document()->instruction(item->address);
        symbol = m_disassembler->document()->symbol(instruction->target());
    }
    else
        symbol = m_disassembler->document()->symbol(item->address);

    if(role == Qt::DisplayRole)
    {
        if(index.column() == 0)
            return QString::fromStdString(REDasm::hex(item->address, m_disassembler->format()->bits(), false));
        else if(index.column() == 1)
        {
            if(item->is(REDasm::ListingItem::FunctionItem))
                return QString::fromStdString(symbol->name);

            return QString::fromStdString(m_printer->out(m_disassembler->document()->instruction(item->address)));
        }
        else if(index.column() == 2)
            return item == m_root ? "---" : QString::number(m_disassembler->getReferencesCount(item->address));
    }
    else if(role == Qt::ForegroundRole)
    {
        if(index.column() == 0)
            return QColor(Qt::darkBlue);
        else if((index.column() == 1) && this->isDuplicate(index) && !symbol->isLocked())
            return QColor(Qt::gray);
    }
    else if(role == Qt::BackgroundColorRole && symbol && symbol->isLocked())
        return THEME_VALUE("locked_bg");
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
