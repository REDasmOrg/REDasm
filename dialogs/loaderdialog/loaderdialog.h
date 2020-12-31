#pragma once

#include <QStandardItemModel>
#include <QDialog>
#include <rdapi/rdapi.h>
#include <deque>
#include "../hooks/isurface.h"

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
        size_t selectedMinString() const;

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
        std::deque<const RDEntryLoader*> m_loaders;
        std::deque<const RDEntryAssembler*> m_assemblers;
        const RDLoaderRequest* m_request;
};
