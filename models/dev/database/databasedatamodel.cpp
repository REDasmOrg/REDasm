#include "databasedatamodel.h"
#include <rdapi/rdapi.h>
#include <QJsonDocument>
#include <cstring>
#include "../../../themeprovider.h"
#include "../../../redasmfonts.h"

namespace fs = std::filesystem;

DatabaseDataModel::DatabaseDataModel(RDDatabase* db, QObject *parent): QAbstractListModel(parent), m_db(db), m_query("/") { }
QString DatabaseDataModel::currentQuery() const { return QString::fromStdString(m_query.string()); }
QString DatabaseDataModel::databaseName() const { return RDDatabase_GetName(m_db); }

QVariant DatabaseDataModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    if(role != Qt::DisplayRole) return QVariant();
    if(orientation != Qt::Horizontal) return QVariant();

    switch(section)
    {
        case 0: return "Key";
        case 1: return "Value";
        default: break;
    }

    return QVariant();
}

int DatabaseDataModel::rowCount(const QModelIndex&) const
{
    if(!m_obj.isEmpty()) return m_obj.size();
    else if(!m_arr.isEmpty()) return m_arr.size();
    return 0;
}

bool DatabaseDataModel::canGoBack() const { return !m_back.empty(); }
bool DatabaseDataModel::canGoForward() const { return !m_forward.empty(); }

bool DatabaseDataModel::decompile(QByteArray& data)
{
    const char* decompiled = RDDatabase_Decompile(m_db);
    if(!decompiled) return false;

    data = QByteArray(decompiled);
    return true;
}

void DatabaseDataModel::goForward()
{
    if(m_forward.empty()) return;

    auto b = m_forward.top();
    m_forward.pop();
    m_back.push(m_query);
    this->query(b);

    emit backChanged();
    emit forwardChanged();
}

void DatabaseDataModel::goBack()
{
    if(m_back.empty()) return;

    auto b = m_back.top();
    m_back.pop();
    m_forward.push(m_query);
    this->query(b);

    emit backChanged();
    emit forwardChanged();
}

void DatabaseDataModel::queryRoot()
{
    m_query = "/";
    this->query();
}

void DatabaseDataModel::query(const QModelIndex& index)
{
    QModelIndex idx = index.sibling(index.row(), 0);
    if(!this->isClickable(idx)) return;

    m_back.push(m_query);
    emit backChanged();

    this->query(fs::path(m_query) / this->data(idx).toString().toStdString());
}

void DatabaseDataModel::query(const fs::path& q) { m_query = q; this->query(); }

void DatabaseDataModel::typeData(const RDDatabaseValue* val)
{
    switch(RDType_GetType(val->t))
    {
        case Type_Structure: {
            break;
        }

        default: break;
    }
}

void DatabaseDataModel::query()
{
    this->beginResetModel();
    m_objkeys.clear();
    m_obj = { };
    m_arr = { };

    RDDatabaseValue val;

    if(RDDatabase_Query(m_db, m_query.string().c_str(), &val))
    {
        QJsonDocument doc;

        switch(val.type)
        {
            case DatabaseValueType_Array:
                doc = QJsonDocument::fromJson(QByteArray::fromRawData(val.arr, std::strlen(val.obj))); break;
                m_arr = doc.array();
                break;

            case DatabaseValueType_Object:
                doc = QJsonDocument::fromJson(QByteArray::fromRawData(val.obj, std::strlen(val.obj)));
                m_obj = doc.object();
                m_objkeys = m_obj.keys();
                break;

            case DatabaseValueType_Type:
                this->typeData(&val);
                break;

            default: break;
        }
    }

    this->endResetModel();
    emit queryChanged(QString::fromStdString(m_query.string()));
}

QString DatabaseDataModel::objectValue(const QJsonValue& v) const
{
    switch(v.type())
    {
        case QJsonValue::Null: return "null";
        case QJsonValue::Object: return "{...}";
        case QJsonValue::Array: return "[...]";
        case QJsonValue::Bool: return v.toBool() ? "TRUE" : "FALSE";
        case QJsonValue::String: return v.toString();
        case QJsonValue::Double: return QString::number(v.toDouble());
        default: break;
    }

    return QString();
}

bool DatabaseDataModel::isClickable(const QModelIndex& index) const
{
    if(!m_obj.isEmpty())
    {
        const auto& v = m_obj[m_objkeys[index.row()]];
        return v.isArray() || v.isObject();
    }
    else if(!m_arr.isEmpty())
    {
        const auto& v = m_arr[index.row()];
        return v.isArray() || v.isObject();
    }

    return false;
}

QVariant DatabaseDataModel::objectData(const QModelIndex& index, int role) const
{
    if((role == Qt::DecorationRole) && (index.column() == 0))
    {
        const auto& v = m_obj[m_objkeys[index.row()]];

        switch(v.type())
        {
            case QJsonValue::Object: return FA_ICON(0xf1b3);
            case QJsonValue::Array:  return FA_ICON(0xf00b);
            case QJsonValue::String: return FA_ICON(0xf031);
            default: break;
        }
    }
    else if((role == Qt::ForegroundRole) && (index.column() == 1))
    {
        const auto& v = m_obj[m_objkeys[index.row()]];

        switch(v.type())
        {
            case QJsonValue::Double: return THEME_VALUE(Theme_Constant);
            case QJsonValue::String: return THEME_VALUE(Theme_String);
            default: break;
        }
    }
    else if(role == Qt::DisplayRole)
    {
        if(index.column() == 0) return m_objkeys[index.row()];
        if(index.column() == 1) return this->objectValue(m_obj[m_objkeys[index.row()]]);
    }

    return this->commonData(index, role);
}

QVariant DatabaseDataModel::arrayData(const QModelIndex& index, int role) const
{
    // if(role == Qt::DecorationRole)
    // {
    //     const auto& v = m_arr[index.row()];

    //     if(v.isObject()) return FA_ICON(0xf1b3);
    //     else if(v.isArray()) return FA_ICON(0xf00b);
    // }
    // else if(role == Qt::DisplayRole) return m_arr[index.row()];

    return this->commonData(index, role);
}

QVariant DatabaseDataModel::commonData(const QModelIndex& index, int role) const
{
    return QVariant();
}

QVariant DatabaseDataModel::data(const QModelIndex &index, int role) const
{
    if(!index.isValid()) return QVariant();

    if(!m_obj.isEmpty()) return this->objectData(index, role);
    else if(!m_arr.isEmpty()) return this->arrayData(index, role);
    return QVariant();
}

int DatabaseDataModel::columnCount(const QModelIndex&) const { return 2; }
