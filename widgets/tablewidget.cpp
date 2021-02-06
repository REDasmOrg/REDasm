#include "tablewidget.h"
#include "ui_tablewidget.h"
#include "../models/listingitemmodel.h"
#include "../themeprovider.h"
#include <QSortFilterProxyModel>
#include <QKeyEvent>

TableWidget::TableWidget(QWidget *parent) : QWidget(parent), ui(new Ui::TableWidget)
{
    ui->setupUi(this);
    ui->leSearch->setVisible(false);
    ui->tbvTable->setShowGrid(false);
    ui->tbvTable->setCornerButtonEnabled(false);
    ui->tbvTable->setAlternatingRowColors(false);
    ui->tbvTable->setSelectionMode(QTableView::SingleSelection);
    ui->tbvTable->setSelectionBehavior(QTableView::SelectRows);
    ui->tbvTable->horizontalHeader()->setHighlightSections(false);
    ui->tbvTable->horizontalHeader()->setStretchLastSection(true);
    ui->tbvTable->verticalHeader()->setHighlightSections(false);
    ui->tbvTable->verticalHeader()->setDefaultSectionSize(ui->tbvTable->verticalHeader()->minimumSectionSize());
    ui->tbvTable->verticalHeader()->setSectionResizeMode(QHeaderView::Fixed);
    ui->tbvTable->verticalHeader()->hide();

    connect(ui->tbvTable, &QTableView::doubleClicked, this, &TableWidget::onTableDoubleClicked);
    connect(ui->tbvTable, &QTableView::clicked, this, &TableWidget::onTableClicked);

    connect(ui->leSearch, &QLineEdit::textChanged, this, [&](const QString& s) {
        static_cast<QSortFilterProxyModel*>(ui->tbvTable->model())->setFilterFixedString(s);
    });
}

TableWidget::~TableWidget()
{
    auto* listingitemmodel = dynamic_cast<ListingItemModel*>(this->model());
    if(listingitemmodel) RDObject_Unsubscribe(listingitemmodel->context().get(), this);
    delete ui;
}

void TableWidget::enableFiltering() { ui->leSearch->setVisible(true); }
void TableWidget::setToggleFilter(bool b) { m_togglefilter = b; }
void TableWidget::setShowVerticalHeader(bool v) { ui->tbvTable->verticalHeader()->setVisible(v); }
void TableWidget::setAlternatingRowColors(bool b) { ui->tbvTable->setAlternatingRowColors(b); }
void TableWidget::setColumnHidden(int idx) { ui->tbvTable->setColumnHidden(idx, true); }
void TableWidget::resizeColumn(int idx) { ui->tbvTable->resizeColumnToContents(idx); }
void TableWidget::moveSection(int from, int to) { ui->tbvTable->horizontalHeader()->moveSection(from, to); }
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

    auto* listingitemmodel = dynamic_cast<ListingItemModel*>(model);
    if(!listingitemmodel || !listingitemmodel->context()) return;

    RDObject_Subscribe(listingitemmodel->context().get(), this, [](const RDEventArgs* e) {
        auto* thethis = reinterpret_cast<TableWidget*>(e->owner);
        auto* lim = dynamic_cast<ListingItemModel*>(thethis->model());

        if((e->id != Event_BusyChanged) || RDContext_IsBusy(lim->context().get())) return;
        Q_EMIT thethis->resizeColumns();
    }, nullptr);
}

QAbstractItemModel* TableWidget::model() const
{
    auto* sfmodel = static_cast<QSortFilterProxyModel*>(ui->tbvTable->model());
    return sfmodel ? sfmodel->sourceModel() : nullptr;
}

void TableWidget::resizeAllColumns() { ui->tbvTable->resizeColumnsToContents(); }

bool TableWidget::event(QEvent* e)
{
    if((e->type() == QEvent::KeyPress) && m_togglefilter)
    {
        QKeyEvent* keyevent = static_cast<QKeyEvent*>(e);

        switch(keyevent->key())
        {
            case Qt::Key_Escape: ui->leSearch->setVisible(false); return true;
            case Qt::Key_F3: ui->leSearch->setVisible(true); return true;
            default: break;
        }
    }

    return QWidget::event(e);
}

void TableWidget::onTableDoubleClicked(const QModelIndex& index)
{
    auto* sfmodel = static_cast<QSortFilterProxyModel*>(ui->tbvTable->model());
    Q_EMIT doubleClicked(sfmodel->mapToSource(index));
}

void TableWidget::onTableClicked(const QModelIndex& index)
{
    auto* sfmodel = static_cast<QSortFilterProxyModel*>(ui->tbvTable->model());
    Q_EMIT clicked(sfmodel->mapToSource(index));
}
