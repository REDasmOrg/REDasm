#include "analyzerdialog.h"
#include "ui_analyzerdialog.h"
#include "../themeprovider.h"
#include <rdapi/rdapi.h>

AnalyzerDialog::AnalyzerDialog(const RDContextPtr& ctx, QWidget *parent) : QDialog(parent), ui(new Ui::AnalyzerDialog), m_context(ctx)
{
    ui->setupUi(this);
    m_analyzersmodel = new QStandardItemModel(ui->tvAnalyzers);
    ui->tvAnalyzers->setModel(m_analyzersmodel);

    this->getAnalyzers();

    connect(m_analyzersmodel, &QStandardItemModel::itemChanged, this, &AnalyzerDialog::onAnalyzerItemChanged);
    connect(ui->pbSelectAll, &QPushButton::clicked, this, [&]() { this->selectAnalyzers(true); });
    connect(ui->pbUnselectAll, &QPushButton::clicked, this, [&]() { this->selectAnalyzers(false); });
    connect(ui->pbRestoreDefaults, &QPushButton::clicked, this, &AnalyzerDialog::getAnalyzers);
}

AnalyzerDialog::~AnalyzerDialog() { delete ui; }

void AnalyzerDialog::selectAnalyzers(bool select)
{
    for(int i = 0; i < m_analyzersmodel->rowCount(); i++)
    {
        auto* item = m_analyzersmodel->item(i);
        const auto* analyzer = reinterpret_cast<const RDAnalyzer*>(item->data().value<void*>());
        if(!analyzer) continue;

        item->setCheckState(select ? Qt::Checked : Qt::Unchecked);
        RDContext_SelectAnalyzer(m_context.get(), analyzer, select);
    }
}

void AnalyzerDialog::onAnalyzerItemChanged(QStandardItem* item)
{
    const auto* analyzer = reinterpret_cast<const RDAnalyzer*>(item->data().value<void*>());
    if(analyzer) RDContext_SelectAnalyzer(m_context.get(), analyzer, (item->checkState() == Qt::Checked));
}

void AnalyzerDialog::getAnalyzers()
{
    m_analyzersmodel->clear();
    m_analyzersmodel->setHorizontalHeaderLabels({"Name", "Description"});

    RDContext_GetAnalyzers(m_context.get(), [](const RDAnalyzer* a, void* userdata) {
        auto* thethis = reinterpret_cast<AnalyzerDialog*>(userdata);
        auto* nameitem = new QStandardItem(QString::fromUtf8(RDAnalyzer_GetName(a)));
        auto* descritem = new QStandardItem(QString::fromUtf8(RDAnalyzer_GetDescription(a)));

        nameitem->setData(QVariant::fromValue(static_cast<void*>(const_cast<RDAnalyzer*>(a))));
        nameitem->setCheckable(true);
        nameitem->setCheckState(RDAnalyzer_IsSelected(a) ? Qt::Checked : Qt::Unchecked);
        if(RDAnalyzer_IsExperimental(a)) nameitem->setForeground(THEME_VALUE(Theme_GraphEdgeFalse));

        thethis->m_analyzersmodel->appendRow({nameitem, descritem});
    }, this);

    ui->tvAnalyzers->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
}
