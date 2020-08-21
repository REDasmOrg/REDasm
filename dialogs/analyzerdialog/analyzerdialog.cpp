#include "analyzerdialog.h"
#include "ui_analyzerdialog.h"

AnalyzerDialog::AnalyzerDialog(const RDLoaderPlugin* ploader, const RDAssemblerPlugin* passembler, QWidget *parent) : QDialog(parent), ui(new Ui::AnalyzerDialog), m_ploader(ploader), m_passembler(passembler)
{
    ui->setupUi(this);
    m_analyzersmodel = new QStandardItemModel(ui->tvAnalyzers);
    ui->tvAnalyzers->setModel(m_analyzersmodel);

    this->syncAnalyzers();

    connect(m_analyzersmodel, &QStandardItemModel::itemChanged, this, &AnalyzerDialog::onAnalyzerItemChanged);
    connect(ui->pbSelectAll, &QPushButton::clicked, this, [&]() { this->selectAnalyzers(true); });
    connect(ui->pbUnselectAll, &QPushButton::clicked, this, [&]() { this->selectAnalyzers(false); });
    connect(ui->pbRestoreDefaults, &QPushButton::clicked, this, &AnalyzerDialog::syncAnalyzers);
}

AnalyzerDialog::~AnalyzerDialog() { delete ui; }

void AnalyzerDialog::selectAnalyzers(bool select)
{
    for(int i = 0; i < m_analyzersmodel->rowCount(); i++)
    {
        auto* item = m_analyzersmodel->item(i);
        const auto* panalyzer = reinterpret_cast<const RDAnalyzerPlugin*>(item->data().value<void*>());
        if(!panalyzer) continue;

        item->setCheckState(select ? Qt::Checked : Qt::Unchecked);
        RDAnalyzer_Select(panalyzer, select);
    }
}

void AnalyzerDialog::onAnalyzerItemChanged(QStandardItem* item)
{
    const auto* panalyzer = reinterpret_cast<const RDAnalyzerPlugin*>(item->data().value<void*>());
    if(panalyzer) RDAnalyzer_Select(panalyzer, (item->checkState() == Qt::Checked));
}

void AnalyzerDialog::syncAnalyzers()
{
    m_analyzersmodel->clear();
    m_analyzersmodel->setHorizontalHeaderLabels({"Name", "Description"});

    RD_GetAnalyzers(m_ploader, m_passembler, [](const RDAnalyzerPlugin* a, void* userdata) {
        auto* thethis = reinterpret_cast<AnalyzerDialog*>(userdata);
        auto* nameitem = new QStandardItem(QString::fromUtf8(a->name));
        auto* descritem = new QStandardItem(QString::fromUtf8(a->description));

        nameitem->setData(QVariant::fromValue(static_cast<void*>(const_cast<RDAnalyzerPlugin*>(a))));
        nameitem->setCheckable(true);
        nameitem->setCheckState(HAS_FLAG(a, AnalyzerFlags_Selected) ? Qt::Checked : Qt::Unchecked);
        if(HAS_FLAG(a, AnalyzerFlags_Experimental)) nameitem->setForeground(THEME_VALUE(Theme_GraphEdgeFalse));

        thethis->m_analyzersmodel->appendRow({nameitem, descritem});
    }, this);

    ui->tvAnalyzers->horizontalHeader()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
}
