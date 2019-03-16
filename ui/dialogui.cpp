#include "dialogui.h"
#include "ui_dialogui.h"
#include <QSortFilterProxyModel>
#include <QPushButton>

DialogUI::DialogUI(QWidget *parent) : QDialog(parent), ui(new Ui::DialogUI)
{
    ui->setupUi(this);

    connect(ui->buttonBox, &QDialogButtonBox::accepted, this, &QDialog::accept);
}

DialogUI::~DialogUI() { delete ui; }
void DialogUI::setText(const QString &s) { ui->lblTitle->setText(s); }

void DialogUI::setItems(REDasm::UI::CheckList &items)
{
    this->createList(new CheckedItemsModel(items));

    connect(ui->pbApply, &QPushButton::clicked, this, [&]() {
        QListView* lvitems = static_cast<QListView*>(ui->stackedWidget->currentWidget());
        QSortFilterProxyModel* filtermodel = static_cast<QSortFilterProxyModel*>(lvitems->model());
        CheckedItemsModel* checkeditemsmodel = static_cast<CheckedItemsModel*>(filtermodel->sourceModel());

        checkeditemsmodel->uncheckAll();

        for(int i = 0; i < filtermodel->rowCount(); i++)
            filtermodel->setData(filtermodel->index(i, 0), Qt::Checked, Qt::CheckStateRole);
    });
}

void DialogUI::createList(QAbstractItemModel* model)
{
    QSortFilterProxyModel* filtermodel = new QSortFilterProxyModel(this);
    filtermodel->setFilterCaseSensitivity(Qt::CaseInsensitive);
    filtermodel->setSourceModel(model);

    QListView* lvitems = new QListView(this);
    lvitems->setUniformItemSizes(true);
    model->setParent(lvitems);

    lvitems->setModel(filtermodel);
    ui->stackedWidget->addWidget(lvitems);

    connect(ui->leFilter, &QLineEdit::textChanged, filtermodel, &QSortFilterProxyModel::setFilterFixedString);
}

void DialogUI::setCanAccept(bool b) { ui->buttonBox->button(QDialogButtonBox::Ok)->setEnabled(b); }

