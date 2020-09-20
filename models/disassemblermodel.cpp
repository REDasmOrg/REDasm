#include "disassemblermodel.h"

DisassemblerModel::DisassemblerModel(QObject *parent) : QAbstractListModel(parent) { }
const RDDisassemblerPtr& DisassemblerModel::disassembler() const { return m_disassembler; }

void DisassemblerModel::setDisassembler(const RDDisassemblerPtr& disassembler)
{
    m_disassembler = disassembler;
    m_document = RDDisassembler_GetDocument(disassembler.get());
}

QVariant DisassemblerModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    Q_UNUSED(section)

    if((orientation == Qt::Horizontal) && (role == Qt::TextAlignmentRole))
        return Qt::AlignCenter;

    return QVariant();
}
