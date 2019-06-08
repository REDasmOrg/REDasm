#ifndef REFERENCESMODEL_H
#define REFERENCESMODEL_H

#include <QJsonObject>
#include <redasm/plugins/assembler/printer/printer.h>
#include "disassemblermodel.h"

class ReferencesModel : public DisassemblerModel
{
    Q_OBJECT

    public:
        explicit ReferencesModel(QObject *parent = 0);
        void setDisassembler(const REDasm::DisassemblerPtr& disassembler) override;
        void xref(address_t address);

    public:
        QModelIndex index(int row, int column, const QModelIndex &) const override;
        QVariant data(const QModelIndex &index, int role) const override;
        QVariant headerData(int section, Qt::Orientation orientation, int role) const override;
        int rowCount(const QModelIndex&) const override;
        int columnCount(const QModelIndex&) const override;

    public slots:
        void clear();

    private:
        QString direction(address_t address) const;

    private:
        REDasm::ReferenceVector m_references;
        REDasm::object_ptr<REDasm::Printer> m_printer;
};

#endif // REFERENCESMODEL_H
