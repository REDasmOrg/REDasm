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

    this->_depends.push_back({ "Capstone", QString("%1.%2").arg(major).arg(minor), "http://www.capstone-engine.org/"});
}

void AboutDialog::initDepends()
{
    ui->twDepends->setRowCount(this->_depends.size());

    for(auto it = this->_depends.begin(); it != this->_depends.end(); it++)
    {
        int index = std::distance(this->_depends.begin(), it);

        ui->twDepends->setItem(index, 0, new QTableWidgetItem(it->name));
        ui->twDepends->setItem(index, 1, new QTableWidgetItem(it->version));
        ui->twDepends->setItem(index, 2, new QTableWidgetItem(it->url));
    }
}
