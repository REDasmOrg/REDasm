#pragma once

#include <rdapi/rdapi.h>
#include <QStandardItemModel>
#include <QDialog>
#include "../hooks/icommand.h"

namespace Ui {
class AnalyzerDialog;
}

class AnalyzerDialog : public QDialog
{
    Q_OBJECT

    public:
        explicit AnalyzerDialog(const RDContextPtr& ctx, QWidget *parent = nullptr);
        ~AnalyzerDialog();

    private:
        void selectAnalyzers(bool select);

    private slots:
        void onAnalyzerItemChanged(QStandardItem* item);
        void getAnalyzers();

    private:
        Ui::AnalyzerDialog *ui;
        QStandardItemModel* m_analyzersmodel;
        RDContextPtr m_context;
};

