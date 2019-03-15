#include "referencesmodel.h"
#include <redasm/disassembler/types/referencetable.h>
#include <redasm/disassembler/listing/listingdocument.h>
#include <redasm/plugins/loader.h>
#include "../themeprovider.h"

ReferencesModel::ReferencesModel(QObject *parent): DisassemblerModel(parent) { }

void ReferencesModel::setDisassembler(REDasm::DisassemblerAPI *disassembler)
{
    DisassemblerModel::setDisassembler(disassembler);
    m_printer = REDasm::PrinterPtr(disassembler->assembler()->createPrinter(disassembler));
}

void ReferencesModel::clear()
{
    this->beginResetModel();
    m_references.clear();
    this->endResetModel();
}

void ReferencesModel::xref(address_t address)
{
    if(!m_disassembler || m_disassembler->busy())
        return;

    this->beginResetModel();
    m_references = m_disassembler->getReferences(address);
    this->endResetModel();
}

QModelIndex ReferencesModel::index(int row, int column, const QModelIndex &) const
{
    if(row >= static_cast<int>(m_references.size()))
        return QModelIndex();

    return this->createIndex(row, column, m_references[row]);
}

QVariant ReferencesModel::data(const QModelIndex &index, int role) const
{
    if(!m_disassembler || m_disassembler->busy())
        return QVariant();

    auto& document = m_disassembler->document();
    auto it = document->instructionItem(m_references[index.row()]);

    if(it == document->end())
        it = document->symbolItem(m_references[index.row()]);

    if(it == document->end())
        return QVariant();

    if(role == Qt::DisplayRole)
    {
        if(index.column() == 0)
            return S_TO_QS(REDasm::hex((*it)->address, m_disassembler->assembler()->bits()));
        else if(index.column() == 1)
            return this->direction((*it)->address);
        else if(index.column() == 2)
        {
            if((*it)->is(REDasm::ListingItem::InstructionItem))
                return QString::fromStdString(m_printer->out(document->instruction((*it)->address)));
            else if((*it)->is(REDasm::ListingItem::SymbolItem))
                return QString::fromStdString(document->symbol((*it)->address)->name);
        }
    }
    else if(role == Qt::ForegroundRole)
    {
        if(index.column() == 0)
            return THEME_VALUE("address_fg");

        if(index.column() == 2)
        {
            if((*it)->is(REDasm::ListingItem::InstructionItem))
            {
                REDasm::InstructionPtr instruction = document->instruction((*it)->address);

                if(!instruction->is(REDasm::InstructionTypes::Conditional))
                    return THEME_VALUE("instruction_jmp_c");
                else if(instruction->is(REDasm::InstructionTypes::Jump))
                    return THEME_VALUE("instruction_jmp");
                else if(instruction->is(REDasm::InstructionTypes::Call))
                    return THEME_VALUE("instruction_call");
            }
            else if((*it)->is(REDasm::ListingItem::SymbolItem))
            {
                const REDasm::Symbol* symbol = document->symbol((*it)->address);

                if(symbol->is(REDasm::SymbolTypes::Data))
                    return THEME_VALUE("data_fg");
                else if(symbol->is(REDasm::SymbolTypes::String))
                    return THEME_VALUE("string_fg");
            }
        }
    }

    return QVariant();
}

QVariant ReferencesModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if(orientation == Qt::Vertical || role != Qt::DisplayRole)
        return QVariant();

    if(section == 0)
        return "Address";
    else if(section == 1)
        return "Direction";
    else if(section == 2)
        return "Reference";

    return QVariant();
}

int ReferencesModel::rowCount(const QModelIndex &) const { return static_cast<int>(m_references.size()); }
int ReferencesModel::columnCount(const QModelIndex &) const { return 3; }

QString ReferencesModel::direction(address_t address) const
{
    REDasm::ListingCursor* cur = m_disassembler->document()->cursor();
    REDasm::ListingItem* item = m_disassembler->document()->itemAt(cur->currentLine());

    if(address > item->address)
        return "Down";

    if(address < item->address)
        return "Up";

    return "---";
}
