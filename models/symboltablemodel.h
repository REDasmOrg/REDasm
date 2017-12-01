#ifndef SYMBOLTABLEMODEL_H
#define SYMBOLTABLEMODEL_H

#include "disassemblermodel.h"

class SymbolTableModel : public DisassemblerModel
{
    Q_OBJECT

    public:
        explicit SymbolTableModel(QObject *parent = 0);
        virtual void setDisassembler(REDasm::Disassembler* disassembler);
        void setSymbolFlags(u32 symbolflags);

    private:
        void loadSymbols();

    public:
        virtual QModelIndex index(int row, int column, const QModelIndex &) const;
        virtual QVariant data(const QModelIndex &index, int role) const;
        virtual QVariant headerData(int section, Qt::Orientation orientation, int role) const;
        virtual int rowCount(const QModelIndex&) const;
        virtual int columnCount(const QModelIndex&) const;

    private:
        REDasm::SymbolTable* _symboltable;
        QList<REDasm::SymbolPtr> _symbols;
        u32 _symbolflags;

    friend class SymbolTableFilterModel;
};

#endif // SYMBOLTABLEMODEL_H
