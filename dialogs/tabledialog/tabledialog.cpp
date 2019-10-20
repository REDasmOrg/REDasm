#include "tabledialog.h"
#include "ui_tabledialog.h"
#include <QSortFilterProxyModel>
#include "../../themeprovider.h"

TableDialog::TableDialog(QWidget *parent) : QDialog(parent), ui(new Ui::TableDialog)
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

TableDialog::~TableDialog() { delete ui; }
void TableDialog::enableFiltering() { ui->leSearch->setVisible(true); }
void TableDialog::setButtonBoxVisible(bool b) { ui->buttonBox->setVisible(b); }

void TableDialog::setModel(QAbstractItemModel* model)
{
    if(!model->parent()) model->setParent(this);
    QSortFilterProxyModel* sfmodel = new QSortFilterProxyModel(this);
    sfmodel->setFilterCaseSensitivity(Qt::CaseInsensitive);
    sfmodel->setFilterKeyColumn(-1);
    sfmodel->setSourceModel(model);
    ui->tbvTable->setModel(sfmodel);

    for(int i = 0; i < model->columnCount(); i++)
        ui->tbvTable->horizontalHeader()->setSectionResizeMode(i, QHeaderView::Stretch);
}
