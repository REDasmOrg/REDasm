#pragma once

#include <QWidget>
#include "../hooks/isurface.h"
#include <rdapi/rdapi.h>

namespace Ui {
class DocumentTab;
}

class DocumentTab : public QWidget
{
    Q_OBJECT

    public:
        explicit DocumentTab(QWidget *parent = nullptr);
        ~DocumentTab();
        void setContext(const RDContextPtr& ctx);
        void updateInformation();

    private:
        DocumentTab& line(const QString& s1, const QString& s2);
        DocumentTab& line(const QString& s = QString());
        DocumentTab& header(const QString& s = QString());
        DocumentTab& string(const QString& k, const QString& s);
        QString blockType(const RDBlock* block) const;
        QString segmentFlags(const RDSegment* segment) const;
        QString addressFlags(RDDocument* doc, rd_address address) const;
        QString padHexDump(const QString& hexdump) const;
        QString getBits(const QByteArray& ba) const;
        QString joinAddressList(const rd_address* addresslist, size_t c) const;
        void displayInstructionInformation(RDDocument* doc, rd_address address);
        void displayNetInformation(rd_address address);
        void displayInformation();

    private:
        template<typename Iterator, typename Func> DocumentTab& array(Iterator begin, Iterator end, const Func& cb);
        template<typename Iterator, typename Func> DocumentTab& array(const QString& k, Iterator begin, Iterator end, const Func& cb);

    private:
        Ui::DocumentTab *ui;
        RDContextPtr m_context;
        int m_indent{0};
};

template<typename Iterator, typename Func> DocumentTab& DocumentTab::array(Iterator begin, Iterator end, const Func& cb) { return this->array(QString(), begin, end, cb); }

template<typename Iterator, typename Func> DocumentTab& DocumentTab::array(const QString& k, Iterator begin, Iterator end, const Func& cb)
{
    QString s;

    for(Iterator it = begin; it != end; it++) {
        if(!s.isEmpty()) s += ", ";
        s += cb(*it);
    }

    return k.isEmpty() ? this->line("[" + s + "]") :
                         this->line(k, "[" + s + "]");
}
