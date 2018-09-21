#include "disassemblermodel.h"

DisassemblerModel::DisassemblerModel(QObject *parent) : QAbstractListModel(parent), m_disassembler(NULL) { }
void DisassemblerModel::setDisassembler(REDasm::DisassemblerAPI *disassembler) { m_disassembler = disassembler; }

QVariant DisassemblerModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    Q_UNUSED(section)

    if((orientation == Qt::Horizontal) && (role == Qt::TextAlignmentRole))
        return Qt::AlignCenter;

    return QVariant();
}

QVariant DisassemblerModel::data(const QModelIndex &index, int role) const
{
    Q_UNUSED(index)

    if(role == Qt::TextAlignmentRole)
        return Qt::AlignCenter;

    return QVariant();
}
