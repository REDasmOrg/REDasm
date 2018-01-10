#ifndef REFERENCESMODEL_H
#define REFERENCESMODEL_H

#include <QJsonObject>
#include "disassemblermodel.h"

class ReferencesModel : public DisassemblerModel
{
    Q_OBJECT

    public:
        explicit ReferencesModel(QObject *parent = 0);
        virtual void setDisassembler(REDasm::Disassembler* disassembler);
        void xref(const REDasm::InstructionPtr &instruction);
        void xref(address_t currentaddress, const REDasm::SymbolPtr &symbol);

    public:
        virtual QModelIndex index(int row, int column, const QModelIndex &) const;
        virtual QVariant data(const QModelIndex &index, int role) const;
        virtual QVariant headerData(int section, Qt::Orientation orientation, int role) const;
        virtual int rowCount(const QModelIndex&) const;
        virtual int columnCount(const QModelIndex&) const;

    public slots:
        void clear();

    private:
        virtual QVariant dataInstructionRefs(const QModelIndex &index, int role) const;
        virtual QVariant dataSymbolRefs(const QModelIndex &index, int role) const;
        QString direction(address_t address) const;

    private:
        std::vector<address_t> _references;
        REDasm::PrinterPtr _printer;
        address_t _currentaddress;
        bool _instructionrefs;
};

#endif // REFERENCESMODEL_H
