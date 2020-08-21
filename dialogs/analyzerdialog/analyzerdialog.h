#pragma once

#include <QStandardItemModel>
#include <QDialog>
#include <rdapi/rdapi.h>
#include "../themeprovider.h"

namespace Ui {
class AnalyzerDialog;
}

class AnalyzerDialog : public QDialog
{
        Q_OBJECT

    public:
        explicit AnalyzerDialog(const RDLoaderPlugin* ploader, const RDAssemblerPlugin* passembler, QWidget *parent = nullptr);
        ~AnalyzerDialog();

    private:
        void selectAnalyzers(bool select);

    private slots:
        void onAnalyzerItemChanged(QStandardItem* item);
        void syncAnalyzers();

    private:
        Ui::AnalyzerDialog *ui;
        QStandardItemModel* m_analyzersmodel;
        const RDLoaderPlugin* m_ploader;
        const RDAssemblerPlugin* m_passembler;
};

