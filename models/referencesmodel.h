#ifndef REFERENCESMODEL_H
#define REFERENCESMODEL_H

#include <QJsonObject>
#include <redasm/plugins/assembler/printer.h>
#include "disassemblermodel.h"

class ReferencesModel : public DisassemblerModel
{
    Q_OBJECT

    public:
        explicit ReferencesModel(QObject *parent = 0);
        virtual void setDisassembler(REDasm::DisassemblerAPI* disassembler);
        void xref(address_t address);

    public:
        virtual QModelIndex index(int row, int column, const QModelIndex &) const;
        virtual QVariant data(const QModelIndex &index, int role) const;
        virtual QVariant headerData(int section, Qt::Orientation orientation, int role) const;
        virtual int rowCount(const QModelIndex&) const;
        virtual int columnCount(const QModelIndex&) const;

    public slots:
        void clear();

    private:
        QString direction(address_t address) const;

    private:
        REDasm::ReferenceVector m_references;
        REDasm::PrinterPtr m_printer;
};

#endif // REFERENCESMODEL_H
