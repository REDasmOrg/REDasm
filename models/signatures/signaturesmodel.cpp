#include "signaturesmodel.h"
#include "../convert.h"
#include <redasm/support/demangler.h>

SignaturesModel::SignaturesModel(QObject *parent): QAbstractListModel(parent), m_signaturedb(nullptr) { }

void SignaturesModel::setSignature(const REDasm::SignatureDB *sigdb)
{
    this->beginResetModel();
    m_signaturedb = sigdb;
    this->endResetModel();
}

QVariant SignaturesModel::data(const QModelIndex &index, int role) const
{
    if(!m_signaturedb || (role != Qt::DisplayRole))
        return QVariant();

    if(index.column() == 0)
    {
        const auto& signature = m_signaturedb->at(index.row());
        return Convert::to_qstring(REDasm::Demangler::demangled(signature["name"]));
    }
    if(index.column() == 1)
        return Convert::to_qstring(m_signaturedb->assembler());
    if(index.column() == 2)
        return static_cast<quint64>(m_signaturedb->size());
    if(index.column() == 3)
    {
        const auto& signature = m_signaturedb->at(index.row());
        return static_cast<quint64>(signature["patterns"].size());
    }
    if(index.column() == 4)
    {
        const auto& signature = m_signaturedb->at(index.row());
        return static_cast<quint64>(signature["patterns"]["symboltype"]);
    }

    return QVariant();
}

QVariant SignaturesModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if((orientation == Qt::Vertical) || (role != Qt::DisplayRole))
        return QVariant();

    if(section == 0)
        return "Name";
    if(section == 1)
        return "Assembler";
    if(section == 2)
        return "Pattern Count";
    if(section == 3)
        return "Size";
    if(section == 4)
        return "Type";

    return QVariant();
}

int SignaturesModel::rowCount(const QModelIndex &) const { return m_signaturedb ? m_signaturedb->size() : 0; }
int SignaturesModel::columnCount(const QModelIndex &) const { return 4; }
