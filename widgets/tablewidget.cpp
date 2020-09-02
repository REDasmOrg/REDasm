#include "tablewidget.h"
#include "ui_tablewidget.h"
#include <QSortFilterProxyModel>
#include "../themeprovider.h"

TableWidget::TableWidget(QWidget *parent) : QWidget(parent), ui(new Ui::TableWidget)
{
    ui->setupUi(this);
    ui->leSearch->setVisible(false);
    ui->tbvTable->setCornerButtonEnabled(true);
    ui->tbvTable->verticalHeader()->setDefaultSectionSize(ui->tbvTable->verticalHeader()->minimumSectionSize());
    ui->tbvTable->verticalHeader()->setSectionResizeMode(QHeaderView::Fixed);

    ThemeProvider::styleCornerButton(ui->tbvTable);

    connect(ui->tbvTable, &QTableView::doubleClicked, this, &TableWidget::onTableDoubleClicked);
    connect(ui->tbvTable, &QTableView::clicked, this, &TableWidget::onTableClicked);

    connect(ui->leSearch, &QLineEdit::textChanged, this, [&](const QString& s) {
        static_cast<QSortFilterProxyModel*>(ui->tbvTable->model())->setFilterFixedString(s);
    });
}

TableWidget::~TableWidget() { delete ui; }
void TableWidget::enableFiltering() { ui->leSearch->setVisible(true); }
void TableWidget::setSelectionModel(QAbstractItemView::SelectionMode mode) { ui->tbvTable->setSelectionMode(mode); }
void TableWidget::setSelectionBehavior(QAbstractItemView::SelectionBehavior behavior) { ui->tbvTable->setSelectionBehavior(behavior); }

void TableWidget::setModel(QAbstractItemModel* model)
{
    if(ui->tbvTable->model()) ui->tbvTable->model()->deleteLater();
    if(!model->parent()) model->setParent(this);

    QSortFilterProxyModel* sfmodel = new QSortFilterProxyModel(this);
    sfmodel->setFilterCaseSensitivity(Qt::CaseInsensitive);
    sfmodel->setFilterKeyColumn(-1);
    sfmodel->setSourceModel(model);
    ui->tbvTable->setModel(sfmodel);

    for(int i = 0; i < model->columnCount(); i++)
        ui->tbvTable->horizontalHeader()->setSectionResizeMode(i, QHeaderView::Stretch);
}

QAbstractItemModel* TableWidget::model() const
{
    auto* sfmodel = static_cast<QSortFilterProxyModel*>(ui->tbvTable->model());
    return sfmodel ? sfmodel->sourceModel() : nullptr;
}

void TableWidget::onTableDoubleClicked(const QModelIndex& index)
{
    auto* sfmodel = static_cast<QSortFilterProxyModel*>(ui->tbvTable->model());
    emit doubleClicked(sfmodel->mapToSource(index));
}

void TableWidget::onTableClicked(const QModelIndex& index)
{
    auto* sfmodel = static_cast<QSortFilterProxyModel*>(ui->tbvTable->model());
    emit clicked(sfmodel->mapToSource(index));
}
