#ifndef REFERENCESMODEL_H
#define REFERENCESMODEL_H

#include <vector>
#include "disassemblermodel.h"
#include "../redasm/disassembler/types/referencetable.h"

class ReferencesModel : public DisassemblerModel
{
    Q_OBJECT

    private:
        typedef std::vector<REDasm::InstructionPtr> ReferenceVector;

    public:
        explicit ReferencesModel(QObject *parent = 0);
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
        QString direction(const REDasm::InstructionPtr& instruction) const;

    private:
        REDasm::ReferenceVector _referencevector;
        address_t _currentaddress;
};

#endif // REFERENCESMODEL_H
