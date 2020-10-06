#pragma once

#include <QAbstractListModel>
#include <rdapi/rdapi.h>
#include "../hooks/idisassemblercommand.h"

class ContextModel : public QAbstractListModel
{
    Q_OBJECT

    public:
        explicit ContextModel(QObject *parent = nullptr);

    public:
        const RDContextPtr& context() const;
        RDDisassembler* disassembler() const;
        virtual void setContext(const RDContextPtr& context);
        QVariant headerData(int section, Qt::Orientation orientation, int role) const override;

    protected:
        RDContextPtr m_context;
        RDDocument* m_document{nullptr};
};
