#include "referencesmodel.h"
#include <redasm/disassembler/listing/backend/referencetable.h>
#include <redasm/plugins/assembler/assembler.h>
#include <redasm/plugins/loader/loader.h>
#include <redasm/support/utils.h>
#include <redasm/redasm.h>
#include "../themeprovider.h"
#include "../convert.h"

ReferencesModel::ReferencesModel(QObject *parent): DisassemblerModel(parent) { m_printer = r_asm->createPrinter(); }

void ReferencesModel::clear()
{
    this->beginResetModel();
    m_references.clear();
    this->endResetModel();
}

void ReferencesModel::xref(address_t address)
{
    if(!r_disasm || r_disasm->busy())
        return;

    this->beginResetModel();
    m_references = r_disasm->getReferences(address);
    this->endResetModel();
}

QModelIndex ReferencesModel::index(int row, int column, const QModelIndex &) const
{
    if(row >= static_cast<int>(m_references.size()))
        return QModelIndex();

    return this->createIndex(row, column, m_references[row].toU64());
}

QVariant ReferencesModel::data(const QModelIndex &index, int role) const
{
    if(!r_disasm || r_disasm->busy()) return QVariant();

    REDasm::ListingItem item = r_doc->itemInstruction(m_references[index.row()].toU64());
    if(!item.isValid()) item = r_doc->itemSymbol(m_references[index.row()].toU64());
    if(!item.isValid()) return QVariant();

    if(role == Qt::DisplayRole)
    {
        if(index.column() == 0) return Convert::to_qstring(REDasm::String::hex(item.address, r_asm->bits()));
        else if(index.column() == 1) return this->direction(item.address);
        else if(index.column() == 2)
        {
            if(item.is(REDasm::ListingItemType::InstructionItem))
                return Convert::to_qstring(m_printer->out(r_doc->instruction(item.address)).simplified());
            else if(item.is(REDasm::ListingItemType::SymbolItem)) {
                return Convert::to_qstring(r_doc->symbol(item.address)->name);
            }
        }
    }
    else if(role == Qt::ForegroundRole)
    {
        if(index.column() == 0) return THEME_VALUE("address_fg");

        if(index.column() == 2)
        {
            if(item.is(REDasm::ListingItemType::InstructionItem))
            {
                REDasm::CachedInstruction instruction = r_doc->instruction(item.address);

                if(!instruction->typeIs(REDasm::InstructionType::Conditional)) return THEME_VALUE("instruction_jmp_c");
                else if(instruction->typeIs(REDasm::InstructionType::Jump)) return THEME_VALUE("instruction_jmp");
                else if(instruction->typeIs(REDasm::InstructionType::Call)) return THEME_VALUE("instruction_call");
            }
            else if(item.is(REDasm::ListingItemType::SymbolItem))
            {
                const REDasm::Symbol* symbol = r_doc->symbol(item.address);
                if(symbol->isData()) return THEME_VALUE("data_fg");
                else if(symbol->isString()) return THEME_VALUE("string_fg");
            }
        }
    }

    return QVariant();
}

QVariant ReferencesModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if(orientation == Qt::Vertical || role != Qt::DisplayRole)
        return QVariant();

    if(section == 0) return "Address";
    else if(section == 1) return "Direction";
    else if(section == 2) return "Reference";

    return QVariant();
}

int ReferencesModel::rowCount(const QModelIndex &) const { return static_cast<int>(m_references.size()); }
int ReferencesModel::columnCount(const QModelIndex &) const { return 3; }

QString ReferencesModel::direction(address_t address) const
{
    REDasm::ListingItem item = r_doc->itemAt(r_doc->cursor().currentLine());

    if(item.isValid())
    {
        if(address > item.address) return "Down";
        if(address < item.address) return "Up";
    }

    return "---";
}
