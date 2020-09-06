#pragma once

#include <QStandardItemModel>
#include <QDialog>

namespace Ui {
class AnalyzerDialog;
}

class AnalyzerDialog : public QDialog
{
    Q_OBJECT

    public:
        explicit AnalyzerDialog(QWidget *parent = nullptr);
        ~AnalyzerDialog();

    private:
        void selectAnalyzers(bool select);

    private slots:
        void onAnalyzerItemChanged(QStandardItem* item);
        void syncAnalyzers();

    private:
        Ui::AnalyzerDialog *ui;
        QStandardItemModel* m_analyzersmodel;
};

