#ifndef ITEMINFORMATIONDIALOG_H
#define ITEMINFORMATIONDIALOG_H

#include <QDialog>
#include <core/disassembler/disassembler.h>

namespace Ui {
class ItemInformationDialog;
}

class ItemInformationDialog : public QDialog
{
    Q_OBJECT

    public:
        explicit ItemInformationDialog(const REDasm::DisassemblerPtr& disassembler, QWidget *parent = nullptr);
        ~ItemInformationDialog();

    private:
        ItemInformationDialog& line(const QString& s1, const QString& s2);
        ItemInformationDialog& line(const QString& s = QString());
        ItemInformationDialog& header(const QString& s = QString());
        ItemInformationDialog& string(const QString& k, const QString& s);
        QString itemType(const REDasm::ListingItem* item) const;
        void displayInformation();

    private:
        template<typename Iterator, typename Func> ItemInformationDialog& array(Iterator begin, Iterator end, const Func& cb);
        template<typename Iterator, typename Func> ItemInformationDialog& array(const QString& k, Iterator begin, Iterator end, const Func& cb);

    private:
        Ui::ItemInformationDialog *ui;
        REDasm::DisassemblerPtr m_disassembler;
};

template<typename Iterator, typename Func> ItemInformationDialog& ItemInformationDialog::array(Iterator begin, Iterator end, const Func& cb) { return this->array(QString(), begin, end, cb); }

template<typename Iterator, typename Func> ItemInformationDialog& ItemInformationDialog::array(const QString& k, Iterator begin, Iterator end, const Func& cb)
{
    QString s;

    for(Iterator it = begin; it != end; it++)
    {
        if(!s.isEmpty())
            s += ", ";

        s += cb(*it);
    }

    return k.isEmpty() ? this->line("[" + s + "]") :
                         this->line(k, "[" + s + "]");
}

#endif // ITEMINFORMATIONDIALOG_H
