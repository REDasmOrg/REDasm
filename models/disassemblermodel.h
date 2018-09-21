#ifndef DISASSEMBLERMODEL_H
#define DISASSEMBLERMODEL_H

#include <QAbstractListModel>
#include <QIdentityProxyModel>
#include "../redasm/disassembler/disassemblerapi.h"

#define S_TO_QS(s) QString::fromStdString(s)

class DisassemblerModel : public QAbstractListModel
{
    Q_OBJECT

    public:
        explicit DisassemblerModel(QObject *parent = 0);

    public:
        virtual void setDisassembler(REDasm::DisassemblerAPI *disassembler);
        virtual QVariant headerData(int section, Qt::Orientation orientation, int role) const;
        virtual QVariant data(const QModelIndex &index, int role) const;

    protected:
        REDasm::DisassemblerAPI* m_disassembler;
        bool m_defaultfont;
};

#endif // DISASSEMBLERMODEL_H
