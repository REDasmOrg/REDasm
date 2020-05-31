#pragma once

#include <QDialog>
#include "../hooks/idisassemblercommand.h"
#include <rdapi/rdapi.h>

namespace Ui {
class ItemInformationDialog;
}

class ItemInformationDialog : public QDialog
{
    Q_OBJECT

    public:
        explicit ItemInformationDialog(IDisassemblerCommand* command, QWidget *parent = nullptr);
        ~ItemInformationDialog();

    private:
        ItemInformationDialog& line(const QString& s1, const QString& s2);
        ItemInformationDialog& line(const QString& s = QString());
        ItemInformationDialog& header(const QString& s = QString());
        ItemInformationDialog& string(const QString& k, const QString& s);
        QString itemType(const RDDocumentItem& item) const;
        QString segmentFlags(const RDSegment* segment) const;
        QString instructionType(const RDInstruction* instruction) const;
        QString instructionFlags(const RDInstruction* instruction) const;
        QString operandType(const RDOperand* operand) const;
        QString symbolType(const RDSymbol* symbol) const;
        QString symbolFlags(const RDSymbol* symbol) const;
        QString padHexDump(const QString& hexdump) const;
        QString getBits(const QByteArray& ba) const;
        void displayInstructionInformation(RDDocument* doc, const RDDocumentItem& item);
        void displaySymbolInformation(RDDocument* doc, const RDDocumentItem& item);
        void displayInformation();

    private:
        template<typename Iterator, typename Func> ItemInformationDialog& array(Iterator begin, Iterator end, const Func& cb);
        template<typename Iterator, typename Func> ItemInformationDialog& array(const QString& k, Iterator begin, Iterator end, const Func& cb);

    private:
        Ui::ItemInformationDialog *ui;
        IDisassemblerCommand* m_command;
        int m_indent{0};
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
