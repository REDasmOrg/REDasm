#pragma once

#include "disassemblermodel.h"
#include <rdapi/rdapi.h>

class ReferencesModel : public DisassemblerModel
{
    Q_OBJECT

    public:
        explicit ReferencesModel(QObject *parent = nullptr);
        ~ReferencesModel();
        void setDisassembler(RDDisassembler* disassembler) override;
        void xref(address_t address, const RDCursor* cursor);

    public:
        QVariant data(const QModelIndex &index, int role) const override;
        QVariant headerData(int section, Qt::Orientation orientation, int role) const override;
        int rowCount(const QModelIndex&) const override;
        int columnCount(const QModelIndex&) const override;

    public slots:
        void clear();

    private:
        QString direction(RDDocument* doc, address_t address) const;

    private:
        RDRenderer* m_renderer{nullptr};
        const RDCursor* m_cursor{nullptr};
        const address_t* m_references{nullptr};
        size_t m_referencescount{0};
};
