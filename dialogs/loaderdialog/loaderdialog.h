#pragma once

#include <QStandardItemModel>
#include <QDialog>
#include <rdapi/rdapi.h>

namespace Ui {
class LoaderDialog;
}

class LoaderDialog : public QDialog
{
    Q_OBJECT

    public:
        explicit LoaderDialog(const RDLoaderRequest *request, QWidget *parent = nullptr);
        ~LoaderDialog();
        RDLoaderBuildRequest buildRequest() const;
        RDLoaderPlugin* selectedLoader() const;
        RDAssemblerPlugin* selectedAssembler() const;

    private:
        rd_flag selectedLoaderFlags() const;
        rd_address baseAddress() const;
        rd_address entryPoint() const;
        rd_offset offset() const;
        void unloadLoaders();
        void unloadAssemblers();
        void checkFlags();
        void validateInput();
        void updateInputMask();
        void syncAssembler();
        void syncAnalyzers();
        void populateAssemblers();

    private slots:
        void onAnalyzerItemChanged(QStandardItem* item);
        void onAccepted();

    private:
        Ui::LoaderDialog *ui;
        QStandardItemModel *m_loadersmodel, *m_analyzersmodel;
        QList<RDLoaderPlugin*> m_loaders;
        QList<RDAssemblerPlugin*> m_assemblers;
        const RDLoaderRequest* m_request;
};
