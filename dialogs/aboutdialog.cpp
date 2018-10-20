#include "aboutdialog.h"
#include "ui_aboutdialog.h"
#include <capstone.h>

AboutDialog::AboutDialog(QWidget *parent) : QDialog(parent), ui(new Ui::AboutDialog)
{
    ui->setupUi(this);
    ui->twDepends->horizontalHeader()->setSectionResizeMode(0, QHeaderView::Stretch);
    ui->twDepends->horizontalHeader()->setSectionResizeMode(1, QHeaderView::ResizeToContents);
    ui->twDepends->horizontalHeader()->setSectionResizeMode(2, QHeaderView::Stretch);

    this->initItems();
    this->initDepends();

    connect(ui->buttonBox, &QDialogButtonBox::accepted, this, &AboutDialog::accept);
}

AboutDialog::~AboutDialog()
{
    delete ui;
}

void AboutDialog::initItems()
{
    int major = 0, minor = 0;
    cs_version(&major, &minor);

    m_depends.push_back({ "Capstone", QString("%1.%2").arg(major).arg(minor), "http://www.capstone-engine.org" });
    m_depends.push_back({ "JSON",     "---",                                  "https://github.com/nlohmann/json" });
    m_depends.push_back({ "D3",       "5.0",                                  "https://d3js.org" });
    m_depends.push_back({ "Dagre",    "0.7.5",                                "https://github.com/dagrejs/dagre" });
    m_depends.push_back({ "Dagre-D3", "0.3.0",                                "https://github.com/dagrejs/dagre-d3" });
}

void AboutDialog::initDepends()
{
    ui->twDepends->setRowCount(static_cast<int>(m_depends.size()));

    for(auto it = m_depends.begin(); it != m_depends.end(); it++)
    {
        int index = std::distance(m_depends.begin(), it);

        ui->twDepends->setItem(index, 0, new QTableWidgetItem(it->name));
        ui->twDepends->setItem(index, 1, new QTableWidgetItem(it->version));
        ui->twDepends->setItem(index, 2, new QTableWidgetItem(it->url));
    }
}
