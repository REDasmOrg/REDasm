#include "disassemblermodel.h"

DisassemblerModel::DisassemblerModel(QObject *parent) : QAbstractListModel(parent), m_disassembler(nullptr) { }
const RDDisassembler* DisassemblerModel::disassembler() const { return m_disassembler; }
void DisassemblerModel::setDisassembler(RDDisassembler* disassembler) { m_disassembler = disassembler; }

QVariant DisassemblerModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    Q_UNUSED(section)

    if((orientation == Qt::Horizontal) && (role == Qt::TextAlignmentRole))
        return Qt::AlignCenter;

    return QVariant();
}
