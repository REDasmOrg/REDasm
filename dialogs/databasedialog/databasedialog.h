#pragma once

#include <QSet>
#include <QDialog>
#include <QToolBar>
#include <unordered_set>
#include <rdapi/rdapi.h>

class DatabaseModel;

namespace Ui {
class DatabaseDialog;
}

class DatabaseDialog: public QDialog
{
    Q_OBJECT

    public:
        explicit DatabaseDialog(QWidget *parent = nullptr);
        ~DatabaseDialog();

    protected:
        void dragEnterEvent(QDragEnterEvent* e) override;
        void dragMoveEvent(QDragMoveEvent* e) override;
        void dropEvent(QDropEvent* e) override;

    private:
        void checkDatabase(const QString& filepath);

    private slots:
        void onDatabaseDataDoubleClicked(const QModelIndex& index);
        void selectDatabase(const QModelIndex& index);
        void updateQuery(const QString& query);
        void checkBackForward();

    private:
        Ui::DatabaseDialog *ui;
        QSet<QString> m_loadeddb;
        DatabaseModel* m_databasemodel;
        QToolBar* m_toolbar;
};

