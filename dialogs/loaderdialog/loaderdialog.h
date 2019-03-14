#ifndef LOADERDIALOG_H
#define LOADERDIALOG_H

#include <QStandardItemModel>
#include <QDialog>
#include <redasm/plugins/plugins.h>

namespace Ui {
class LoaderDialog;
}

class LoaderDialog : public QDialog
{
    Q_OBJECT

    public:
        explicit LoaderDialog(const REDasm::LoaderList& loaders, QWidget *parent = nullptr);
        const REDasm::LoaderPlugin_Entry *selectedLoader() const;
        const REDasm::AssemblerPlugin_Entry *selectedAssembler() const;
        address_t baseAddress() const;
        address_t entryPoint() const;
        offset_t offset() const;
        u32 selectedLoaderFlags() const;
        ~LoaderDialog();

    private:
        void checkFlags();
        void updateInputMask();
        void populateAssemblers();

    private:
        Ui::LoaderDialog *ui;
        QStandardItemModel* m_loadersmodel;
        const REDasm::LoaderList& m_loaders;
};

#endif // LOADERDIALOG_H
