#include "tabletab.h"
#include "ui_tabletab.h"
#include "../../../models/listingitemmodel.h"
#include "../hooks/disassemblerhooks.h"
#include "../hooks/icommandtab.h"
#include "../redasmfonts.h"
#include <QSortFilterProxyModel>
#include <QKeyEvent>

TableTab::TableTab(ListingItemModel* model, QWidget *parent): QWidget(parent), ui(new Ui::TableTab), m_listingitemmodel(model)
{
    model->setDisassembler(DisassemblerHooks::instance()->activeCommand()->disassembler());

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

    m_filtermodel = new QSortFilterProxyModel();
    m_filtermodel->setFilterCaseSensitivity(Qt::CaseInsensitive);
    m_filtermodel->setFilterKeyColumn(-1);
    m_filtermodel->setSourceModel(model);
    ui->tvTable->setModel(m_filtermodel);

    connect(ui->leFilter, &QLineEdit::textChanged, m_filtermodel, &QSortFilterProxyModel::setFilterFixedString);
    connect(ui->tvTable, &QTreeView::doubleClicked, this, &TableTab::onTableDoubleClick);
    connect(ui->pbClear, &QPushButton::clicked, ui->leFilter, &QLineEdit::clear);

    RDEvent_Subscribe(this, [](const RDEventArgs* e) {
        auto* thethis = reinterpret_cast<TableTab*>(e->owner);
        if((e->eventid != Event_BusyChanged) || RD_IsBusy()) return;
        emit thethis->resizeColumns();
    }, nullptr);
}

TableTab::~TableTab() { RDEvent_Unsubscribe(this); delete ui; }
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

    DisassemblerHooks::instance()->activeCommand()->gotoItem(item);
    DisassemblerHooks::instance()->focusOn(DisassemblerHooks::instance()->activeCommandTab()->widget());
}

bool TableTab::event(QEvent* e)
{
    if(e->type() == QEvent::KeyPress)
    {
        QKeyEvent* keyevent = static_cast<QKeyEvent*>(e);

        if(keyevent->key() == Qt::Key_Escape)
        {
            ui->pbClear->setVisible(false);
            ui->leFilter->setVisible(false);
            ui->leFilter->clear();
        }
    }

    return QWidget::event(e);
}

void TableTab::toggleFilter()
{
    ui->pbClear->setVisible(!ui->pbClear->isVisible());
    ui->leFilter->setVisible(!ui->leFilter->isVisible());

    if(ui->leFilter->isVisible()) ui->leFilter->setFocus();
    else ui->leFilter->clear();
}
