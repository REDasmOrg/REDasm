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
        flag_t selectedLoaderFlags() const;
        address_t baseAddress() const;
        address_t entryPoint() const;
        offset_t offset() const;
        void unloadLoaders();
        void unloadAssemblers();
        void checkFlags();
        void validateInput();
        void updateInputMask();
        void syncAssembler();
        void populateAssemblers();

    private slots:
        void onAccepted();

    private:
        Ui::LoaderDialog *ui;
        QStandardItemModel* m_loadersmodel;
        QList<RDLoaderPlugin*> m_loaders;
        QList<RDAssemblerPlugin*> m_assemblers;
        const RDLoaderRequest* m_request;
};
