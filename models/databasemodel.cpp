#include "databasemodel.h"
#include <QMessageBox>
#include <QFontDatabase>
#include <QColor>
#include "../redasm/signatures/patparser.h"

DatabaseModel::DatabaseModel(QObject *parent) : QAbstractListModel(parent) { }

void DatabaseModel::loadPats(const QStringList &patfiles)
{
    REDasm::PatParser patparser;
    m_signaturedb.setSignatureType(REDasm::SignatureDB::IDASignature);
    this->beginResetModel();

    std::for_each(patfiles.begin(), patfiles.end(), [this, &patparser](const QString& file) {
        patparser.load(file.toStdString());
    });

    m_signaturedb << patparser.signatures();
    this->endResetModel();
}

bool DatabaseModel::save(const QString& name, const QString &file)
{
    return m_signaturedb.write(name.toStdString(), file.toStdString());
}

QVariant DatabaseModel::data(const QModelIndex &index, int role) const
{
    if(role == Qt::DisplayRole)
    {
        const REDasm::Signature& signature = m_signaturedb[index.row()];

        if(index.column() == 0)
            return QString::fromStdString(signature.name);
        else if(index.column() == 1)
            return QString::fromStdString(signature.pattern);
        else if(index.column() == 2)
            return QString::fromStdString(REDasm::hex(static_cast<u16>(signature.alen), 8));
        else if(index.column() == 3)
            return QString::fromStdString(REDasm::hex(signature.asum, 16));
    }
    else if(role == Qt::ForegroundRole)
    {
        if(index.column() == 1)
            return QColor(Qt::gray);
        else if(index.column() > 1)
            return QColor(Qt::darkBlue);
    }
    else if((role == Qt::FontRole) && (index.column() > 0))
        return QFontDatabase::systemFont(QFontDatabase::FixedFont);

    return QVariant();
}

QVariant DatabaseModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if(orientation == Qt::Vertical || role != Qt::DisplayRole)
        return QVariant();

    if(section == 0)
        return "Name";
    else if(section == 1)
        return "Pattern";
    else if(section == 2)
        return "Length";
    else if(section == 3)
        return "CRC Length";

    return QVariant();
}

int DatabaseModel::rowCount(const QModelIndex &) const
{
    return m_signaturedb.count();
}

int DatabaseModel::columnCount(const QModelIndex &) const
{
    return 4;
}
