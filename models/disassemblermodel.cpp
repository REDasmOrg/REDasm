#include "disassemblermodel.h"
#include <QFontDatabase>

DisassemblerModel::DisassemblerModel(QObject *parent) : QAbstractListModel(parent), m_disassembler(NULL), m_defaultfont(false) {  }

void DisassemblerModel::setDefaultFont(bool b)
{
    this->beginResetModel();
    m_defaultfont = b;
    this->endResetModel();
}

void DisassemblerModel::setDisassembler(REDasm::DisassemblerAPI *disassembler) { m_disassembler = disassembler; }

QVariant DisassemblerModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    Q_UNUSED(section)

    if(role == Qt::TextAlignmentRole)
        return Qt::AlignCenter;

    return QVariant();
}

QVariant DisassemblerModel::data(const QModelIndex &index, int role) const
{
    Q_UNUSED(index)

    if(role == Qt::TextAlignmentRole)
        return Qt::AlignCenter;
    else if((role == Qt::FontRole) && !m_defaultfont)
        return QFontDatabase::systemFont(QFontDatabase::FixedFont);

    return QVariant();
}
