#include "referencesmodel.h"
#include "../themeprovider.h"
#include "../hooks/disassemblerhooks.h"
#include "../renderer/surfaceqt.h"
#include <array>

#define ADD_REFERENCE_FLAG(s, t) { if(!s.isEmpty()) s += " | ";  s += t; }

ReferencesModel::ReferencesModel(QObject *parent): ContextModel(parent)
{
    m_surface = DisassemblerHooks::instance()->activeSurface();
}

void ReferencesModel::clear()
{
    this->beginResetModel();
    m_referencescount = 0;
    m_references = nullptr;
    this->endResetModel();
}

QString ReferencesModel::referenceFlags(const RDReference& reference) const
{
    QString s;
    if(HAS_FLAG(&reference, ReferenceFlags_Direct))   ADD_REFERENCE_FLAG(s, "DIRECT");
    if(HAS_FLAG(&reference, ReferenceFlags_Indirect)) ADD_REFERENCE_FLAG(s, "INDIRECT");
    if(HAS_FLAG(&reference, ReferenceFlags_Manual))   ADD_REFERENCE_FLAG(s, "MANUAL");
    return s;
}

void ReferencesModel::xref(rd_address address)
{
    if(!m_context || RDContext_IsBusy(m_context.get())) return;

    this->beginResetModel();
    const RDNet* net = RDContext_GetNet(m_context.get());
    m_referencescount = RDNet_GetReferences(net, address, &m_references);

    this->endResetModel();
}

QModelIndex ReferencesModel::index(int row, int column, const QModelIndex&) const
{
    if(row >= static_cast<int>(m_referencescount)) return QModelIndex();

    return this->createIndex(row, column, m_references[row].address);
}

QVariant ReferencesModel::data(const QModelIndex &index, int role) const
{
    if(!m_context || RDContext_IsBusy(m_context.get())) return QVariant();

    RDDocument* doc = RDContext_GetDocument(m_context.get());
    auto& r = m_references[index.row()];

    if(role == Qt::DisplayRole)
    {
        if(index.column() == 0) return RD_ToHexAuto(m_context.get(), r.address);
        else if(index.column() == 1) return this->referenceFlags(m_references[index.row()]);
        else if(index.column() == 2) return this->direction(r.address);
        else if(index.column() == 3)
        {
            const char* label = RDDocument_GetLabel(doc, r.address);
            return label ? label : RD_GetInstruction(m_context.get(), r.address);
        }
    }
    else if(role == Qt::TextAlignmentRole)
    {
        if(index.column() == 0) return Qt::AlignRight + Qt::AlignVCenter;
        if(index.column() == 3) return Qt::AlignLeft + Qt::AlignVCenter;
        return Qt::AlignCenter;
    }
    else if((role == Qt::ForegroundRole) && (index.column() == 0))
        return THEME_VALUE(Theme_Address);

    return QVariant();
}

QVariant ReferencesModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if(orientation == Qt::Vertical || role != Qt::DisplayRole)
        return QVariant();

    if(section == 0) return "Address";
    else if(section == 1) return "Flags";
    else if(section == 2) return "Direction";
    else if(section == 3) return "Reference";

    return QVariant();
}

int ReferencesModel::rowCount(const QModelIndex &) const { return m_referencescount; }
int ReferencesModel::columnCount(const QModelIndex &) const { return 4; }

QString ReferencesModel::direction(rd_address address) const
{
    if(!m_surface) return QString();

    rd_address curraddress = m_surface->currentAddress();

    if(curraddress != RD_NVAL)
    {
        if(address > curraddress) return "Down";
        if(address < curraddress) return "Up";
    }

    return "---";
}
