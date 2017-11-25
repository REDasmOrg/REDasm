#include "disassemblermodel.h"

DisassemblerModel::DisassemblerModel(QObject *parent) : QAbstractListModel(parent), _disassembler(NULL)
{

}

void DisassemblerModel::setDisassembler(REDasm::Disassembler *disassembler)
{
    this->_disassembler = disassembler;
}
