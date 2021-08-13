#include "tablewidget.h"
#include "ui_tablewidget.h"
#include "../models/contextmodel.h"
#include "../themeprovider.h"
#include <QSortFilterProxyModel>
#include <QKeyEvent>
#include <QAction>

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
    ui->leSearch->setFrame(false);

    m_actfilter = new QAction(tr("Filter"), ui->tbvTable);
    connect(m_actfilter, &QAction::triggered, this, [&]() { this->showFilter(); } );
    ui->tbvTable->setContextMenuPolicy(Qt::ActionsContextMenu);

    connect(ui->tbvTable, &QTableView::doubleClicked, this, &TableWidget::onTableDoubleClicked);
    connect(ui->tbvTable, &QTableView::clicked, this, &TableWidget::onTableClicked);

    connect(ui->leSearch, &QLineEdit::textChanged, this, [&](const QString& s) {
        static_cast<QSortFilterProxyModel*>(ui->tbvTable->model())->setFilterFixedString(s);
    });
}

TableWidget::~TableWidget()
{
    auto* contextmodel = dynamic_cast<ContextModel*>(this->model());
    if(contextmodel && contextmodel->context()) RDObject_Unsubscribe(contextmodel->context().get(), this);
    delete ui;
}

void TableWidget::enableFiltering() { ui->leSearch->setVisible(true); }

void TableWidget::setToggleFilter(bool b)
{
    m_togglefilter = b;
    if(b) ui->tbvTable->addAction(m_actfilter);
    else ui->tbvTable->removeAction(m_actfilter);
}

void TableWidget::setShowVerticalHeader(bool v) { ui->tbvTable->verticalHeader()->setVisible(v); }
void TableWidget::setAlternatingRowColors(bool b) { ui->tbvTable->setAlternatingRowColors(b); }
void TableWidget::setColumnHidden(int idx) { ui->tbvTable->setColumnHidden(idx, true); }
void TableWidget::resizeColumn(int idx) { ui->tbvTable->resizeColumnToContents(idx); }
void TableWidget::resizeColumnsUntil(int offset) { for(int i = 0; i < ui->tbvTable->model()->columnCount() - offset; i++) ui->tbvTable->resizeColumnToContents(i); }
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

    auto* contextmodel = dynamic_cast<ContextModel*>(model);
    if(!contextmodel || !contextmodel->context()) return;

    RDObject_Subscribe(contextmodel->context().get(), this, [](const RDEventArgs* e) {
        auto* thethis = reinterpret_cast<TableWidget*>(e->owner);
        auto* cm = dynamic_cast<ContextModel*>(thethis->model());

        if((e->id != Event_BusyChanged) || RDContext_IsBusy(cm->context().get())) return;
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
            case Qt::Key_Escape: this->clearFilter(); return true;
            case Qt::Key_F3: this->showFilter(); return true;
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

void TableWidget::clearFilter()
{
    ui->leSearch->setVisible(false);
    ui->leSearch->clear();
}

void TableWidget::showFilter()
{
    ui->leSearch->setVisible(true);
    ui->leSearch->setFocus();
}
