#ifndef FORMATLOADERDIALOG_H
#define FORMATLOADERDIALOG_H

#include <QStandardItemModel>
#include <QDialog>
#include <redasm/plugins/plugins.h>

namespace Ui {
class FormatLoaderDialog;
}

class FormatLoaderDialog : public QDialog
{
    Q_OBJECT

    public:
        explicit FormatLoaderDialog(const QString& ext, REDasm::LoaderEntryListByExt* loaders, QWidget *parent = nullptr);
        ~FormatLoaderDialog();

    public:
        bool discarded() const;
        REDasm::LoaderPlugin* loadSelectedLoader(REDasm::AbstractBuffer* buffer);

    private:
        void loadFormats();

    private:
        Ui::FormatLoaderDialog *ui;
        QStandardItemModel* m_loadersmodel;
        REDasm::LoaderEntryListByExt* m_loaders;
        bool m_discarded;
};

#endif // FORMATLOADERDIALOG_H
