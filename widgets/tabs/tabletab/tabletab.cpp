#include "tabletab.h"
#include "ui_tabletab.h"
#include "../../../models/listingitemmodel.h"
#include "../../../renderer/surfaceqt.h"
#include "../hooks/disassemblerhooks.h"
#include "../redasmfonts.h"
#include <QSortFilterProxyModel>
#include <QKeyEvent>
#include <QAction>

TableTab::TableTab(ListingItemModel* model, QWidget *parent): QWidget(parent), ui(new Ui::TableTab), m_listingitemmodel(model)
{
    model->setContext(DisassemblerHooks::instance()->activeContext());

    ui->setupUi(this);
    ui->tvTable->header()->setStretchLastSection(true);
    ui->tvTable->setUniformRowHeights(true);
    ui->leFilter->setVisible(false);

    ui->leFilter->setStyleSheet(QString("QLineEdit {"
                                            "border-top-color: %1;"
                                            "border-top-style: solid;"
                                            "border-top-width: 1px;"
                                        "}").arg(qApp->palette().color(QPalette::Window).name()));

    ui->pbClear->setVisible(false);
    ui->pbClear->setText(QString());
    ui->pbClear->setIcon(FA_ICON(0xf00d));

    m_filtermodel = new QSortFilterProxyModel(this);
    m_filtermodel->setFilterCaseSensitivity(Qt::CaseInsensitive);
    m_filtermodel->setFilterKeyColumn(-1);
    m_filtermodel->setSourceModel(model);
    ui->tvTable->setModel(m_filtermodel);

    connect(ui->leFilter, &QLineEdit::textChanged, m_filtermodel, &QSortFilterProxyModel::setFilterFixedString);
    connect(ui->tvTable, &QTreeView::doubleClicked, this, &TableTab::onTableDoubleClick);
    connect(ui->pbClear, &QPushButton::clicked, ui->leFilter, &QLineEdit::clear);

    auto* actfilter = new QAction("Filter", ui->tvTable);
    connect(actfilter, &QAction::triggered, this, [&]() { this->setFilterVisible(true); } );
    ui->tvTable->setContextMenuPolicy(Qt::ActionsContextMenu);
    ui->tvTable->addAction(actfilter);

    RDObject_Subscribe(model->context().get(), this, [](const RDEventArgs* e) {
        auto* thethis = reinterpret_cast<TableTab*>(e->owner);
        if((e->id != Event_BusyChanged) || RDContext_IsBusy(thethis->m_listingitemmodel->context().get())) return;
        Q_EMIT thethis->resizeColumns();
    }, nullptr);
}

TableTab::~TableTab() { RDObject_Unsubscribe(m_listingitemmodel->context().get(), this); delete ui; }
ListingItemModel* TableTab::model() const { return m_listingitemmodel; }
void TableTab::setSectionResizeMode(int idx, QHeaderView::ResizeMode mode) { ui->tvTable->header()->setSectionResizeMode(idx, mode); }
void TableTab::setColumnHidden(int idx) { ui->tvTable->setColumnHidden(idx, true); }
void TableTab::resizeColumn(int idx) { ui->tvTable->resizeColumnToContents(idx); }
void TableTab::moveSection(int from, int to) { ui->tvTable->header()->moveSection(from, to); }
void TableTab::resizeAllColumns() { for(int i = 0; i < ui->tvTable->model()->columnCount(); i++) this->resizeColumn(i); }

void TableTab::onTableDoubleClick(const QModelIndex& index)
{
    QModelIndex srcindex = m_filtermodel->mapToSource(index);
    const RDDocumentItem& item = m_listingitemmodel->item(srcindex);

    auto* surface = DisassemblerHooks::instance()->activeSurface();
    if(!surface) return;

    surface->goTo(&item);
    //DisassemblerHooks::instance()->focusOn(surface->widget());
}

bool TableTab::event(QEvent* e)
{
    if(e->type() == QEvent::KeyPress)
    {
        QKeyEvent* keyevent = static_cast<QKeyEvent*>(e);

        switch(keyevent->key())
        {
            case Qt::Key_Escape: this->setFilterVisible(false); return true;
            case Qt::Key_F3: this->setFilterVisible(true); return true;
            default: break;
        }
    }

    return QWidget::event(e);
}

void TableTab::setFilterVisible(bool b)
{
    ui->pbClear->setVisible(b);
    ui->leFilter->setVisible(b);

    if(ui->leFilter->isVisible()) ui->leFilter->setFocus();
    else ui->leFilter->clear();
}
