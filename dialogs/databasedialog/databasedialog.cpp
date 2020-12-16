#include "databasedialog.h"
#include "ui_databasedialog.h"
#include "../redasmfonts.h"
#include "../models/dev/database/databasemodel.h"
#include <QFileDialog>
#include <QDragEnterEvent>
#include <QDirIterator>
#include <QMessageBox>
#include <QMimeData>

DatabaseDialog::DatabaseDialog(const RDContextPtr& ctx, QWidget *parent) : QDialog(parent), ui(new Ui::DatabaseDialog)
{
    ui->setupUi(this);
    this->setAcceptDrops(true);

    ui->splitter->setStretchFactor(1, 1);
    ui->pbBack->setIcon(FA_ICON(0xf104));
    ui->pbForward->setIcon(FA_ICON(0xf105));
    ui->pbRoot->setIcon(FA_ICON(0xf015));
    ui->pbExport->setIcon(FA_ICON(0xf56e));

    ui->twDatabaseData->setSelectionBehavior(QAbstractItemView::SelectRows);
    ui->twDatabaseData->enableFiltering();

    m_databasemodel = new DatabaseModel(this);
    ui->lvDatabase->setModel(m_databasemodel);

    connect(ui->lvDatabase->selectionModel(), &QItemSelectionModel::currentChanged, this, &DatabaseDialog::selectDatabase);
    connect(ui->twDatabaseData, &TableWidget::doubleClicked, this, &DatabaseDialog::onDatabaseDataDoubleClicked);

    connect(ui->pbBack, &QPushButton::clicked, this, [&]() {
        auto* dbdatamodel = static_cast<DatabaseDataModel*>(ui->twDatabaseData->model());
        if(dbdatamodel) dbdatamodel->goBack();
    });

    connect(ui->pbForward, &QPushButton::clicked, this, [&]() {
        auto* dbdatamodel = static_cast<DatabaseDataModel*>(ui->twDatabaseData->model());
        if(dbdatamodel) dbdatamodel->goForward();
    });

    connect(ui->pbRoot, &QPushButton::clicked, this, [&]() {
        auto* dbdatamodel = static_cast<DatabaseDataModel*>(ui->twDatabaseData->model());
        if(dbdatamodel) dbdatamodel->queryRoot();
    });

    connect(ui->pbExport, &QPushButton::clicked, this, [&]() {
        auto* dbdatamodel = static_cast<DatabaseDataModel*>(ui->twDatabaseData->model());
        if(!dbdatamodel) return;

        QByteArray decompiled;

        if(!dbdatamodel->decompile(decompiled)) {
            QMessageBox::information(this, "Decompilation Failed", QString("Cannot decompile '%1'").arg(dbdatamodel->databaseName()));
            return;
        }

        QString s = QFileDialog::getSaveFileName(this, "Export Database", QString("%1.json").arg(dbdatamodel->databaseName()), "REDasm Source Database (*.json)");
        if(s.isEmpty()) return;

        QFile f(s);
        f.open(QFile::WriteOnly);
        f.write(decompiled);
    });

    RDConfig_GetDatabasePaths([](const char* path, void* userdata) {
        auto* thethis = reinterpret_cast<DatabaseDialog* >(userdata);
        QDirIterator it(path, {"*" DATABASE_RDB_EXT}, QDir::Files, QDirIterator::Subdirectories | QDirIterator::FollowSymlinks);
        while(it.hasNext()) thethis->checkDatabase(it.next());
    }, this);

    if(ctx) this->addDatabase(RDContext_GetDatabase(ctx.get()));
}

DatabaseDialog::~DatabaseDialog() { delete ui; }

void DatabaseDialog::dragEnterEvent(QDragEnterEvent* e)
{
    if(!e->mimeData()->hasUrls()) return;
    e->acceptProposedAction();
}

void DatabaseDialog::dragMoveEvent(QDragMoveEvent* e)
{
    if(!e->mimeData()->hasUrls()) return;
    e->acceptProposedAction();
}

void DatabaseDialog::dropEvent(QDropEvent* e)
{
    const QMimeData* mimedata = e->mimeData();
    if(!mimedata->hasUrls()) return;

    QList<QUrl> urllist = mimedata->urls();
    QString locfile = urllist.first().toLocalFile();

    QFileInfo fi(locfile);
    if(!fi.isFile()) return;

    this->checkDatabase(locfile);
    e->acceptProposedAction();
}

void DatabaseDialog::checkBackForward()
{
    auto* dbdatamodel = static_cast<DatabaseDataModel*>(ui->twDatabaseData->model());
    if(!dbdatamodel) return;

    ui->pbBack->setEnabled(dbdatamodel->canGoBack());
    ui->pbForward->setEnabled(dbdatamodel->canGoForward());
}

void DatabaseDialog::checkDatabase(const QString& filepath)
{
    if(m_loadeddb.contains(filepath)) return;
    m_loadeddb.insert(filepath);

    RDDatabase* db = RDDatabase_Open(qUtf8Printable(filepath));
    if(db) this->addDatabase(db);
}

void DatabaseDialog::addDatabase(RDDatabase* db)
{
    QModelIndex index = m_databasemodel->addDatabase(db);
    if(ui->twDatabaseData->model()) return;

    DatabaseDataModel* dbdatamodel = m_databasemodel->dataModel(index);
    connect(dbdatamodel, &DatabaseDataModel::queryChanged, this, &DatabaseDialog::updateQuery);
    connect(dbdatamodel, &DatabaseDataModel::forwardChanged, this, &DatabaseDialog::checkBackForward);
    connect(dbdatamodel, &DatabaseDataModel::backChanged, this, &DatabaseDialog::checkBackForward);
    ui->twDatabaseData->setModel(dbdatamodel);
    this->updateQuery(dbdatamodel->currentQuery());
}

void DatabaseDialog::onDatabaseDataDoubleClicked(const QModelIndex& index)
{
    auto* dbdatamodel = static_cast<DatabaseDataModel*>(ui->twDatabaseData->model());
    if(!dbdatamodel) return;

    dbdatamodel->query(index);
    this->checkBackForward();
}

void DatabaseDialog::selectDatabase(const QModelIndex& index)
{
    DatabaseDataModel* dbdatamodel = m_databasemodel->dataModel(index);
    ui->twDatabaseData->setModel(dbdatamodel);
    this->updateQuery(dbdatamodel->currentQuery());
}

void DatabaseDialog::updateQuery(const QString& query)
{
    auto* dbdatamodel = static_cast<DatabaseDataModel*>(ui->twDatabaseData->model());
    if(!dbdatamodel || (dbdatamodel->currentQuery() != query)) return;

    ui->lblQuery->setText(query);
    this->checkBackForward();
}
