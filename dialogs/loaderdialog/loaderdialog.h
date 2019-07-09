#ifndef LOADERDIALOG_H
#define LOADERDIALOG_H

#include <QStandardItemModel>
#include <QDialog>
#include <redasm/plugins/pluginmanager.h>

namespace Ui {
class LoaderDialog;
}

class LoaderDialog : public QDialog
{
    Q_OBJECT

    public:
        explicit LoaderDialog(const REDasm::LoadRequest &request, QWidget *parent = nullptr);
        ~LoaderDialog();
        const REDasm::PluginInstance* selectedLoader() const;
        const REDasm::PluginInstance* selectedAssembler() const;
        REDasm::LoaderFlags selectedLoaderFlags() const;
        address_t baseAddress() const;
        address_t entryPoint() const;
        offset_t offset() const;

    private:
        void unloadLoaders();
        void unloadAssemblers();
        void checkFlags();
        void validateInput();
        void updateInputMask();
        void syncAssembler();
        void populateAssemblers();

    private:
        Ui::LoaderDialog *ui;
        QStandardItemModel* m_loadersmodel;
        REDasm::PluginManager::PluginList m_loaders, m_assemblers;
        const REDasm::LoadRequest& m_request;
};

#endif // LOADERDIALOG_H
