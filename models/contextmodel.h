#pragma once

#include <QAbstractListModel>
#include <rdapi/rdapi.h>
#include "../hooks/isurface.h"

class ContextModel : public QAbstractListModel
{
    Q_OBJECT

    public:
        explicit ContextModel(const RDContextPtr& ctx, QObject *parent = nullptr);
        explicit ContextModel(QObject *parent = nullptr);

    public:
        const RDContextPtr& context() const;
        const RDDocument* document() const;
        virtual void setContext(const RDContextPtr& context);
        QVariant headerData(int section, Qt::Orientation orientation, int role) const override;

    protected:
        RDContextPtr m_context;
        RDDocument* m_document{nullptr};
};
