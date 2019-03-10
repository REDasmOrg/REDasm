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
        explicit FormatLoaderDialog(const QString& ext, REDasm::FormatEntryListByExt* formats, QWidget *parent = nullptr);
        ~FormatLoaderDialog();

    public:
        bool discarded() const;
        REDasm::FormatPlugin* loadSelectedFormat(REDasm::AbstractBuffer* buffer);

    private:
        void loadFormats();

    private:
        Ui::FormatLoaderDialog *ui;
        QStandardItemModel* m_formatsmodel;
        REDasm::FormatEntryListByExt* m_formats;
        bool m_discarded;
};

#endif // FORMATLOADERDIALOG_H
