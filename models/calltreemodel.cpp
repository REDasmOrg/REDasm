#include "calltreemodel.h"
#include <redasm/plugins/assembler/assembler.h>
#include <redasm/plugins/loader/loader.h>
#include <redasm/support/utils.h>
#include <redasm/redasm.h>
#include "../themeprovider.h"
#include "../convert.h"
#include <QFontDatabase>
#include <QColor>

CallTreeModel::CallTreeModel(QObject *parent) : QAbstractItemModel(parent), m_disassembler(nullptr), m_root(nullptr) { }

void CallTreeModel::setDisassembler(const REDasm::DisassemblerPtr &disassembler)
{
    m_disassembler = disassembler;
    m_printer = r_asm->createPrinter();
}

void CallTreeModel::initializeGraph(address_t address)
{
    this->clearGraph();

    REDasm::ListingDocument& document = m_disassembler->document();
    REDasm::ListingItem* item = document->functionItem(address);

    if(!item)
        return;

    m_root = item;
    m_depths[m_root] = 0;
    m_parents[m_root] = nullptr;
    this->populate(m_root);
}

void CallTreeModel::clearGraph()
{
    this->beginResetModel();
    m_root = nullptr;
    m_depths.clear();
    m_children.clear();
    m_parents.clear();
    this->endResetModel();
}

void CallTreeModel::populateCallGraph(const QModelIndex &index) { this->populate(reinterpret_cast<REDasm::ListingItem*>(index.internalPointer())); }

void CallTreeModel::populate(REDasm::ListingItem* parentitem)
{
    if(m_children.contains(parentitem))
        return;

    REDasm::SortedList calls;

    if(parentitem->is(REDasm::ListingItemType::InstructionItem))
    {
        auto location = this->getCallTarget(parentitem);

        if(location.valid)
            calls = m_disassembler->getCalls(location);
    }
    else if(parentitem->is(REDasm::ListingItemType::FunctionItem))
        calls = m_disassembler->getCalls(parentitem->address());

    if(calls.empty())
        return;

    QModelIndex index;

    if(parentitem != m_root)
        index = this->createIndex(this->getParentIndex(parentitem), 0, const_cast<REDasm::ListingItem*>(parentitem));

    this->beginInsertRows(index, 0, static_cast<int>(calls.size()));
    m_children[parentitem] = calls;

    for(size_t i = 0; i < m_children[parentitem].size(); i++)
    {
        REDasm::ListingItem* item = variant_object<REDasm::ListingItem>(m_children[parentitem][i]);
        m_parents[item] = parentitem;

        if(!m_depths.contains(item))
            m_depths[item] = m_depths[parentitem] + 1;
    }

    this->endInsertRows();
}

bool CallTreeModel::isDuplicate(const QModelIndex &index) const
{
    REDasm::ListingItem* item = reinterpret_cast<REDasm::ListingItem*>(index.internalPointer());

    if(item == m_root)
        return false;

    QModelIndex parentindex = this->parent(index);
    REDasm::ListingItem* parentitem = reinterpret_cast<REDasm::ListingItem*>(parentindex.internalPointer());
    return (m_depths[item] - m_depths[parentitem]) != 1;
}

int CallTreeModel::getParentIndexFromChild(REDasm::ListingItem *childitem) const
{
    if(childitem == m_root)
        return -1;

    REDasm::ListingItem* parentitem = m_parents[childitem];
    return this->getParentIndex(parentitem);
}

int CallTreeModel::getParentIndex(REDasm::ListingItem *parentitem) const
{
    const REDasm::SortedList& parentlist = m_children[m_parents[parentitem]];
    return parentlist.indexOf(parentitem);
}

address_location CallTreeModel::getCallTarget(const REDasm::ListingItem *item) const
{
    if(!item->is(REDasm::ListingItemType::InstructionItem))
        return REDasm::invalid_location<address_t>();

    REDasm::CachedInstruction instruction = m_disassembler->document()->instruction(item->address());

    if(!instruction->is(REDasm::InstructionType::Call))
        return REDasm::invalid_location<address_t>();

    return m_disassembler->getTarget(item->address());
}

bool CallTreeModel::hasChildren(const QModelIndex &parentindex) const
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
        const REDasm::SortedList& children = m_children[parentitem];

        if(children.empty())
            return false;
    }

    if(parentitem->is(REDasm::ListingItemType::InstructionItem))
    {
        auto location = this->getCallTarget(parentitem);
        return location.valid ? !m_disassembler->getCalls(location).empty() : false;
    }

    return true;
}

QModelIndex CallTreeModel::index(int row, int column, const QModelIndex &parent) const
{
    if(!m_disassembler || !m_root || m_children.empty())
        return QModelIndex();

    REDasm::ListingItem* parentitem = reinterpret_cast<REDasm::ListingItem*>(parent.internalPointer());

    if(!parentitem)
        return this->createIndex(row, column, const_cast<REDasm::ListingItem*>(m_root));

    return this->createIndex(row, column, variant_object<REDasm::ListingItem>(m_children[parentitem][row]));
}

QModelIndex CallTreeModel::parent(const QModelIndex &child) const
{
    if(!m_disassembler || !m_root)
        return QModelIndex();

    REDasm::ListingItem* childitem = reinterpret_cast<REDasm::ListingItem*>(child.internalPointer());

    if(childitem == m_root)
        return QModelIndex();

    REDasm::ListingItem* parentitem = m_parents[childitem];
    return this->createIndex(this->getParentIndexFromChild(childitem), 0, const_cast<REDasm::ListingItem*>(parentitem));
}

QVariant CallTreeModel::headerData(int section, Qt::Orientation orientation, int role) const
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

QVariant CallTreeModel::data(const QModelIndex &index, int role) const
{
    if(!m_disassembler || m_disassembler->busy() || !m_root)
        return QVariant();

    auto lock = REDasm::s_lock_safe_ptr(m_disassembler->document());
    REDasm::ListingItem* item = reinterpret_cast<REDasm::ListingItem*>(index.internalPointer());
    const REDasm::Symbol* symbol = lock->symbol(item->address());

    if(item->is(REDasm::ListingItemType::InstructionItem))
    {
        REDasm::ReferenceSet refs = m_disassembler->getTargets(item->address());

        if(!refs.empty())
            symbol = lock->symbol(*refs.begin());
    }

    if(role == Qt::DisplayRole)
    {
        if(index.column() == 0)
            return Convert::to_qstring(REDasm::String::hex(item->address(), m_disassembler->assembler()->bits()));
        else if(index.column() == 1)
        {
            if(item->is(REDasm::ListingItemType::FunctionItem))
                return Convert::to_qstring(symbol->name);

            return Convert::to_qstring(m_printer->out(lock->instruction(item->address())));
        }
        else if(index.column() == 2)
            return item == m_root ? "---" : QString::number(m_disassembler->getReferencesCount(item->address()));
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

int CallTreeModel::columnCount(const QModelIndex &parent) const { Q_UNUSED(parent) return 3; }

int CallTreeModel::rowCount(const QModelIndex &parent) const
{
    if(!m_disassembler || m_disassembler->busy() || !m_root || m_children.empty())
        return 0;

    REDasm::ListingItem* parentitem = reinterpret_cast<REDasm::ListingItem*>(parent.internalPointer());

    if(!parentitem)
        return 1;

    return static_cast<int>(m_children[parentitem].size());
}
