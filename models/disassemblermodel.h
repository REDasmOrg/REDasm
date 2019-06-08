#ifndef DISASSEMBLERMODEL_H
#define DISASSEMBLERMODEL_H

#include <QAbstractListModel>
#include <QIdentityProxyModel>
#include <redasm/disassembler/disassembler.h>

#define S_TO_QS(s) QString::fromStdString(s)

class DisassemblerModel : public QAbstractListModel
{
    Q_OBJECT

    public:
        explicit DisassemblerModel(QObject *parent = nullptr);

    public:
        virtual void setDisassembler(const REDasm::DisassemblerPtr& disassembler);
        QVariant headerData(int section, Qt::Orientation orientation, int role) const override;

    protected:
        REDasm::DisassemblerPtr m_disassembler;
};

#endif // DISASSEMBLERMODEL_H
