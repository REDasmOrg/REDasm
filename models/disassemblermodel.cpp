#include "disassemblermodel.h"

DisassemblerModel::DisassemblerModel(QObject *parent) : QAbstractListModel(parent), m_disassembler(NULL) {  }
void DisassemblerModel::setDisassembler(REDasm::Disassembler *disassembler) { m_disassembler = disassembler; }
