#include "calltreemodel.h"
#include "../themeprovider.h"
#include <QFontDatabase>
#include <QColor>

CallTreeModel::CallTreeModel(QObject *parent) : QAbstractItemModel(parent) { }

const RDDocumentItem& CallTreeModel::item(const QModelIndex& index) const
{
    //REDasm::CallNode* node = reinterpret_cast<REDasm::CallNode*>(index.internalPointer());
    //return node->data;
}

void CallTreeModel::setContext(const RDContextPtr& ctx) { m_context = ctx; /* m_printer = r_asm->createPrinter(); */ }

void CallTreeModel::initializeGraph(rd_address address)
{
    // REDasm::ListingItem item = r_doc->functionStart(address);
    // if(m_currentitem == item) return;

    // this->beginResetModel();

    // if(item.isValid()) m_calltree = std::make_unique<REDasm::CallTree>(item);
    // else m_calltree = nullptr;

    // this->endResetModel();
}

void CallTreeModel::populateCallGraph(const QModelIndex &index)
{
    //REDasm::CallNode* node = reinterpret_cast<REDasm::CallNode*>(index.internalPointer());
    //if(!node->empty()) return;

    //size_t c = node->populate();
    //if(!c) return;
    //this->beginInsertRows(index, 0, c);
    //this->endInsertRows();
}

bool CallTreeModel::hasChildren(const QModelIndex& parentindex) const
{
    //if(!r_disasm || r_disasm->busy() || !m_calltree) return QAbstractItemModel::hasChildren(parentindex);

    //REDasm::CallNode* parentnode = reinterpret_cast<REDasm::CallNode*>(parentindex.internalPointer());
    //if(!parentnode) return true;
    //return parentnode->hasCalls();
}

QModelIndex CallTreeModel::index(int row, int column, const QModelIndex &parent) const
{
    //if(!r_disasm || r_disasm->busy() || !m_calltree) return QModelIndex();

    //REDasm::CallNode* parentnode = reinterpret_cast<REDasm::CallNode*>(parent.internalPointer());
    //if(!parentnode) return this->createIndex(row, column, m_calltree.get());
    //return this->createIndex(row, column, parentnode->at(row));
}

QModelIndex CallTreeModel::parent(const QModelIndex &child) const
{
    //if(!r_disasm || r_disasm->busy() || !m_calltree) return QModelIndex();

    //REDasm::CallNode* childnode = reinterpret_cast<REDasm::CallNode*>(child.internalPointer());
    //if(childnode == m_calltree.get()) return QModelIndex();
    //return this->createIndex(childnode->parent()->index(), 0, childnode->parent());
}

QVariant CallTreeModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if(orientation != Qt::Horizontal) return QVariant();

    if(role == Qt::DisplayRole)
    {
        if(section == 0) return "Address";
        if(section == 1) return "Value";
        if(section == 2) return "R";
    }
    else if(role == Qt::TextAlignmentRole)
        return Qt::AlignCenter;

    return QVariant();
}

QVariant CallTreeModel::data(const QModelIndex &index, int role) const
{
    // if(!r_disasm || r_disasm->busy() || !m_calltree)
    //     return QVariant();

    // REDasm::CallNode* node = reinterpret_cast<REDasm::CallNode*>(index.internalPointer());
    // if(!node) return QVariant();

    // const REDasm::ListingItem& item = node->data;
    // const REDasm::Symbol* symbol = r_doc->symbol(item.address);

    // if(item.is(REDasm::ListingItem::InstructionItem))
    // {
    //     REDasm::SortedSet refs = r_disasm->getTargets(item.address);
    //     if(!refs.empty()) symbol = r_doc->symbol(refs.first().toU64());
    // }

    // if(role == Qt::DisplayRole)
    // {
    //     if(index.column() == 0)
    //         return Convert::to_qstring(REDasm::String::hex(item.address, r_asm->bits()));
    //     else if(index.column() == 1)
    //     {
    //         if(item.is(REDasm::ListingItem::FunctionItem)) return Convert::to_qstring(symbol->name);
    //         return Convert::to_qstring(m_printer->out(r_doc->instruction(item.address)));
    //     }
    //     else if(index.column() == 2)
    //         return node == m_calltree.get() ? "---" : QString::number(r_disasm->getReferencesCount(item.address));
    // }
    // else if((role == Qt::ForegroundRole) && (index.column() == 0)) return THEME_VALUE("address_fg");
    // else if((role == Qt::TextAlignmentRole) && (index.column() == 2)) return Qt::AlignCenter;

    return QVariant();
}

int CallTreeModel::columnCount(const QModelIndex &parent) const { Q_UNUSED(parent) return 3; }

int CallTreeModel::rowCount(const QModelIndex &parent) const
{
    //if(!r_disasm|| r_disasm->busy() || !m_calltree) return 0;
    //REDasm::CallNode* parentnode = reinterpret_cast<REDasm::CallNode*>(parent.internalPointer());
    //if(!parentnode) return 1;
    //return parentnode->size();
    return 0;
}
