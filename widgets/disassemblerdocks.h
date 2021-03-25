#pragma once

#include <QObject>
#include <QSet>
#include <future>
#include <rdapi/rdapi.h>
#include <kddockwidgets/DockWidget.h>
#include "disassemblertabs/disassemblertabs.h"

class ContextModel;
class TableWidget;
class DockWidget;

class DisassemblerDocks : public QObject
{
    Q_OBJECT

    public:
        explicit DisassemblerDocks(QObject *parent = nullptr);
        virtual ~DisassemblerDocks();
        const RDContextPtr& context() const;
        void setContext(const RDContextPtr& ctx);
        DockWidget* showListing() const;
        void showSegments() const;
        void showFunctions() const;
        void showExports() const;
        void showImports() const;
        void showStrings() const;
        void showMap(KDDockWidgets::DockWidget* relative = nullptr) const;

    private Q_SLOTS:
        void onItemDoubleClicked(const QModelIndex& index);
        void showDisassembly();

    private:
        TableWidget* createTable(ContextModel* model, const QString& title) const;
        static void listenEvents(const RDEventArgs* e);

    private:
        RDContextPtr m_context;
        std::future<void> m_worker;
        DockWidget* m_analysisdock;
};
