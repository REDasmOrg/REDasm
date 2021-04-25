#include "qtdialogui.h"
#include "ui_qtdialogui.h"
#include <QSortFilterProxyModel>
#include <QPushButton>

QtDialogUI::QtDialogUI(QWidget *parent) : QDialog(parent), ui(new Ui::QtDialogUI)
{
    ui->setupUi(this);
    connect(ui->buttonBox, &QDialogButtonBox::accepted, this, &QDialog::accept);
}

QtDialogUI::~QtDialogUI() { delete ui; }
int QtDialogUI::selectedIndex() const { return m_selectedindex; }
void QtDialogUI::setText(const QString &s) { ui->lblTitle->setText(s); }

void QtDialogUI::setCheckedOptions(RDUIOptions* options, size_t c)
{
    this->createList(new CheckedItemsModel(options, c));

    connect(ui->pbApply, &QPushButton::clicked, this, [&]() {
        QListView* lvitems = static_cast<QListView*>(ui->stackedWidget->currentWidget());
        QSortFilterProxyModel* filtermodel = static_cast<QSortFilterProxyModel*>(lvitems->model());
        CheckedItemsModel* checkeditemsmodel = static_cast<CheckedItemsModel*>(filtermodel->sourceModel());

        checkeditemsmodel->uncheckAll();

        for(int i = 0; i < filtermodel->rowCount(); i++)
            filtermodel->setData(filtermodel->index(i, 0), Qt::Checked, Qt::CheckStateRole);
    });
}

void QtDialogUI::hideFilter()
{
    ui->leFilter->setVisible(false);
    ui->pbApply->setVisible(false);
}

void QtDialogUI::createList(QAbstractItemModel* model)
{
    QSortFilterProxyModel* filtermodel = new QSortFilterProxyModel(this);
    filtermodel->setFilterCaseSensitivity(Qt::CaseInsensitive);
    filtermodel->setSortRole(Qt::CheckStateRole);
    filtermodel->setSourceModel(model);
    filtermodel->sort(0, Qt::DescendingOrder);

    QListView* lvitems = new QListView(this);
    lvitems->setUniformItemSizes(true);
    model->setParent(lvitems);

    lvitems->setModel(filtermodel);
    ui->stackedWidget->addWidget(lvitems);

    connect(lvitems->selectionModel(), &QItemSelectionModel::currentRowChanged, this, [&](const QModelIndex &current, const QModelIndex&) {
        m_selectedindex = current.row();
    });

    connect(ui->leFilter, &QLineEdit::textChanged, filtermodel, &QSortFilterProxyModel::setFilterFixedString);
}

void QtDialogUI::setCanAccept(bool b) { ui->buttonBox->button(QDialogButtonBox::Ok)->setEnabled(b); }
