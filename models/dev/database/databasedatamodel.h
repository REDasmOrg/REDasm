#pragma once

#include <QAbstractListModel>
#include <rdapi/rdapi.h>
#include <QJsonObject>
#include <QJsonArray>
#include <stack>

class DatabaseDataModel : public QAbstractListModel
{
    Q_OBJECT

    public:
        explicit DatabaseDataModel(RDDatabase* db, QObject *parent = nullptr);
        QString currentQuery() const;
        QString databaseName() const;
        QVariant headerData(int section, Qt::Orientation orientation, int role) const override;
        QVariant data(const QModelIndex &index, int role = Qt::DisplayRole) const override;
        int columnCount(const QModelIndex&) const override;
        int rowCount(const QModelIndex&) const override;
        bool canGoBack() const;
        bool canGoForward() const;
        bool decompile(QByteArray& data);
        void query(const QModelIndex& index);

    public slots:
        void goForward();
        void goBack();
        void queryRoot();
        void query();

    private:
        void query(const std::string& q);
        QString objectValue(const QJsonValue& v) const;
        bool isClickable(const QModelIndex& index) const;
        QVariant objectData(const QModelIndex& index, int role) const;
        QVariant arrayData(const QModelIndex& index, int role) const;
        QVariant commonData(const QModelIndex& index, int role) const;

    signals:
        void backChanged();
        void forwardChanged();
        void queryChanged(const QString& query);

    private:
        std::stack<std::string> m_back, m_forward;
        RDDatabase* m_db;
        std::string m_query;
        QStringList m_objkeys;
        QJsonObject m_obj;
        QJsonArray m_arr;
};

