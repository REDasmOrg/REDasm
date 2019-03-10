#include "formatloaderdialog.h"
#include "ui_formatloaderdialog.h"

FormatLoaderDialog::FormatLoaderDialog(QWidget *parent) : QDialog(parent), ui(new Ui::FormatLoaderDialog)
{
    ui->setupUi(this);
}

FormatLoaderDialog::~FormatLoaderDialog()
{
    delete ui;
}
