#include "tabletab.h"
#include "ui_tabletab.h"
#include "../../../models/listingitemmodel.h"
#include "../hooks/disassemblerhooks.h"
#include "../hooks/icommandtab.h"
#include "../redasmfonts.h"
#include <QSortFilterProxyModel>
#include <QKeyEvent>

TableTab::TableTab(ICommandTab* commandtab, ListingItemModel* model, QWidget *parent): QWidget(parent), ui(new Ui::TableTab), m_commandtab(commandtab), m_listingitemmodel(model)
{
    model->setDisassembler(commandtab->command()->disassembler());

    ui->setupUi(this);
    ui->leFilter->setVisible(false);

    ui->leFilter->setStyleSheet(QString("QLineEdit {"
                                            "border-top-color: %1;"
                                            "border-top-style: solid;"
                                            "border-top-width: 1px;"
                                        "}").arg(qApp->palette().color(QPalette::Window).name()));

    ui->pbClear->setVisible(false);
    ui->pbClear->setText(QString());
    ui->pbClear->setIcon(FA_ICON(0xf00d));

    ui->tbvTable->verticalHeader()->setDefaultSectionSize(ui->tbvTable->verticalHeader()->minimumSectionSize());

    m_filtermodel = new QSortFilterProxyModel();
    m_filtermodel->setFilterCaseSensitivity(Qt::CaseInsensitive);
    m_filtermodel->setFilterKeyColumn(-1);
    m_filtermodel->setSourceModel(model);
    ui->tbvTable->setModel(m_filtermodel);

    connect(ui->leFilter, &QLineEdit::textChanged, m_filtermodel, &QSortFilterProxyModel::setFilterFixedString);
    connect(ui->tbvTable, &QTableView::doubleClicked, this, &TableTab::onTableDoubleClick);
    connect(ui->pbClear, &QPushButton::clicked, ui->leFilter, &QLineEdit::clear);
}

TableTab::~TableTab() { delete ui; }
ListingItemModel* TableTab::model() const { return m_listingitemmodel; }
void TableTab::setSectionResizeMode(int idx, QHeaderView::ResizeMode mode) { ui->tbvTable->horizontalHeader()->setSectionResizeMode(idx, mode); }
void TableTab::setColumnHidden(int idx) { ui->tbvTable->setColumnHidden(idx, true); }
void TableTab::moveSection(int from, int to) { ui->tbvTable->horizontalHeader()->moveSection(from, to); }

void TableTab::onTableDoubleClick(const QModelIndex& index)
{
    QModelIndex srcindex = m_filtermodel->mapToSource(index);
    const RDDocumentItem& item = m_listingitemmodel->item(srcindex);

    m_commandtab->command()->gotoItem(item);
    DisassemblerHooks::instance()->focusOn(m_commandtab->widget());
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
