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

    connect(ui->leSearch, &QLineEdit::textChanged, this, [&](const QString& s) {
        static_cast<QSortFilterProxyModel*>(ui->tbvTable->model())->setFilterFixedString(s);
    });
}

TableWidget::~TableWidget() { delete ui; }
void TableWidget::enableFiltering() { ui->leSearch->setVisible(true); }

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
