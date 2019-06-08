#ifndef LOADERDIALOG_H
#define LOADERDIALOG_H

#include <QStandardItemModel>
#include <QDialog>
#include <redasm/plugins/loader/loader.h>
#include <redasm/plugins/assembler/assembler.h>

namespace Ui {
class LoaderDialog;
}

class LoaderDialog : public QDialog
{
    Q_OBJECT

    public:
        explicit LoaderDialog(const REDasm::LoadRequest& request, QWidget *parent = nullptr);
        const REDasm::Loader *selectedLoader() const;
        const REDasm::Assembler *selectedAssembler() const;
        address_t baseAddress() const;
        address_t entryPoint() const;
        offset_t offset() const;
        REDasm::LoaderFlags selectedLoaderFlags() const;
        ~LoaderDialog();

    private:
        void checkFlags();
        void validateInput();
        void updateInputMask();
        void populateAssemblers();

    private:
        Ui::LoaderDialog *ui;
        QStandardItemModel* m_loadersmodel;
        //REDasm::LoaderList m_loaders;
        const REDasm::LoadRequest& m_request;
};

#endif // LOADERDIALOG_H
