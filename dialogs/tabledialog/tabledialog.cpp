#include "tabledialog.h"
#include "ui_tabledialog.h"
#include "../widgets/tablewidget.h"

TableDialog::TableDialog(QWidget *parent) : QDialog(parent), ui(new Ui::TableDialog)
{
    ui->setupUi(this);

    connect(ui->buttonBox, &QDialogButtonBox::accepted, this, &TableDialog::accept);
    connect(ui->buttonBox, &QDialogButtonBox::rejected, this, &TableDialog::reject);
}

TableDialog::~TableDialog() { delete ui; }
void TableDialog::enableFiltering() { ui->tableWidget->enableFiltering(); }
void TableDialog::setButtonBoxVisible(bool b) { ui->buttonBox->setVisible(b); }
void TableDialog::setModel(QAbstractItemModel* model) { ui->tableWidget->setModel(model); }
