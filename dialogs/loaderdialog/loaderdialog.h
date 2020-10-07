#pragma once

#include <QStandardItemModel>
#include <QDialog>
#include <rdapi/rdapi.h>
#include "../hooks/icommand.h"

namespace Ui {
class LoaderDialog;
}

class LoaderDialog : public QDialog
{
    Q_OBJECT

    public:
        explicit LoaderDialog(RDContextPtr& ctx, const RDLoaderRequest *req, QWidget *parent = nullptr);
        ~LoaderDialog();
        RDLoaderBuildParams buildRequest() const;
        const RDEntryLoader* selectedLoaderEntry() const;
        const RDEntryAssembler* selectedAssemblerEntry() const;

    private:
        rd_flag selectedLoaderFlags() const;
        rd_address baseAddress() const;
        rd_address entryPoint() const;
        rd_offset offset() const;
        void unloadLoaders();
        void unloadAssemblers();
        void checkFlags();
        void validateFields();
        void updateInputMask();
        void syncAssemblerEntry(const RDContextPtr& ctx);
        void populateAssemblerEntries(const RDContextPtr& ctx);

    private:
        Ui::LoaderDialog *ui;
        QStandardItemModel *m_loadersmodel, *m_analyzersmodel;
        QList<const RDEntryLoader*> m_loaders;
        QList<const RDEntryAssembler*> m_assemblers;
        const RDLoaderRequest* m_request;
};
