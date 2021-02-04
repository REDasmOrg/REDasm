#pragma once

#include <rdapi/rdapi.h>
#include <QStandardItemModel>
#include <QDialog>
#include "../hooks/isurface.h"

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
        void setOrderColumnVisible(bool v);

    private Q_SLOTS:
        void onAnalyzerItemChanged(QStandardItem* item);
        void getAnalyzers();

    private:
        Ui::AnalyzerDialog *ui;
        QStandardItemModel* m_analyzersmodel;
        RDContextPtr m_context;
};

