#include "disassemblermodel.h"

DisassemblerModel::DisassemblerModel(QObject *parent) : QAbstractListModel(parent), m_disassembler(NULL) {  }
void DisassemblerModel::setDisassembler(REDasm::DisassemblerAPI *disassembler) { m_disassembler = disassembler; }
