#include "contextmodel.h"

ContextModel::ContextModel(const RDContextPtr& ctx, QObject *parent): QAbstractListModel(parent), m_context(ctx)
{
    m_document = RDContext_GetDocument(ctx.get());

    RDObject_Subscribe(ctx.get(), this, [](const RDEventArgs* e) {
        auto thethis = reinterpret_cast<ContextModel*>(e->owner);
        if((e->id != Event_BusyChanged) || RDContext_IsBusy(thethis->m_context.get())) return;

        // Trigger model update
        thethis->beginResetModel();
        thethis->endResetModel();
    }, nullptr);
}

ContextModel::ContextModel(QObject* parent): QAbstractListModel(parent) { }
ContextModel::~ContextModel() { RDObject_Unsubscribe(m_context.get(), this); }
const RDContextPtr& ContextModel::context() const { return m_context; }
const RDDocument* ContextModel::document() const { return m_document; }

void ContextModel::setContext(const RDContextPtr& context)
{
    m_context = context;
    m_document = RDContext_GetDocument(context.get());
}

QVariant ContextModel::headerData(int section, Qt::Orientation orientation, int role) const
{
    Q_UNUSED(section)

    if((orientation == Qt::Horizontal) && (role == Qt::TextAlignmentRole))
        return Qt::AlignCenter;

    return QVariant();
}
