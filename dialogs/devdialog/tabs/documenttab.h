#pragma once

#include <QWidget>
#include "../hooks/idisassemblercommand.h"
#include <rdapi/rdapi.h>

namespace Ui {
class DocumentTab;
}

class DocumentTab : public QWidget
{
    Q_OBJECT

    public:
        explicit DocumentTab(QWidget *parent = nullptr);
        void setCommand(IDisassemblerCommand* command);
        Q_INVOKABLE void updateInformation();
        ~DocumentTab();

    private:
        DocumentTab& line(const QString& s1, const QString& s2);
        DocumentTab& line(const QString& s = QString());
        DocumentTab& header(const QString& s = QString());
        DocumentTab& string(const QString& k, const QString& s);
        QString itemType(const RDDocumentItem& item) const;
        QString segmentFlags(const RDSegment* segment) const;
        QString symbolType(const RDSymbol* symbol) const;
        QString symbolFlags(const RDSymbol* symbol) const;
        QString padHexDump(const QString& hexdump) const;
        QString getBits(const QByteArray& ba) const;
        void displayInstructionInformation(RDDocument* doc, const RDDocumentItem& item);
        void displaySymbolInformation(RDDocument* doc, const RDDocumentItem& item);
        void displayInformation();

    private:
        template<typename Iterator, typename Func> DocumentTab& array(Iterator begin, Iterator end, const Func& cb);
        template<typename Iterator, typename Func> DocumentTab& array(const QString& k, Iterator begin, Iterator end, const Func& cb);

    private:
        Ui::DocumentTab *ui;
        IDisassemblerCommand* m_command{nullptr};
        int m_indent{0};
};

template<typename Iterator, typename Func> DocumentTab& DocumentTab::array(Iterator begin, Iterator end, const Func& cb) { return this->array(QString(), begin, end, cb); }

template<typename Iterator, typename Func> DocumentTab& DocumentTab::array(const QString& k, Iterator begin, Iterator end, const Func& cb)
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
