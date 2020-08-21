#pragma once

#define HOOK_TOOLBAR             "toolBar"
#define HOOK_TABS                "tabs"
#define HOOK_STATUS_ICON         "lblStatusIcon"
#define HOOK_PROBLEMS            "pbProblems"
#define HOOK_RENDERER            "pbRenderer"
#define HOOK_MENU_WINDOW         "menu_Window"
#define HOOK_ACTION_SAVE_AS      "action_Save_As"
#define HOOK_ACTION_CLOSE        "action_Close"
#define HOOK_ACTION_RECENT_FILES "action_Recent_Files"
#define HOOK_ACTION_DEVTOOLS     "action_Developer_Tools"

#include <QMainWindow>
#include <QPushButton>
#include <QLabel>
#include <QFileInfo>
#include <future>
#include <rdapi/rdapi.h>
#include "../widgets/disassemblertabs/disassemblertabs.h"
#include "icommandtab.h"
#include "itabletab.h"

class DevDialog;
class OutputDock;
class DisassemblerView;
class ListingItemModel;
class TableTab;
struct RDDisassembler;
struct RDBuffer;

class DisassemblerHooks: public QObject
{
    Q_OBJECT

    private:
        enum { Action_Rename = 0, Action_XRefs, Action_Follow, Action_FollowPointerHexDump,
               Action_CallGraph, Action_Goto, Action_HexDump, Action_HexDumpFunction, Action_Comment, Action_CreateFunction,
               Action_Back, Action_Forward, Action_Copy };

    private:
        DisassemblerHooks(QObject* parent = nullptr);
        ~DisassemblerHooks();

    public:
        static void initialize(QMainWindow* mainwindow);
        static DisassemblerHooks* instance();

    public slots:
        void log(const QString& s);
        void clearLog();
        void resetLayout();
        void open();
        void close();
        void save();
        void saveAs();
        void settings();
        void about();
        void exit();

    public:
        ITableTab* showSegments(Qt::DockWidgetArea area = Qt::NoDockWidgetArea);
        ITableTab* showFunctions(Qt::DockWidgetArea area = Qt::NoDockWidgetArea);
        ITableTab* showExports(Qt::DockWidgetArea area = Qt::NoDockWidgetArea);
        ITableTab* showImports(Qt::DockWidgetArea area = Qt::NoDockWidgetArea);
        ITableTab* showStrings(Qt::DockWidgetArea area = Qt::NoDockWidgetArea);
        QMenu* createActions(IDisassemblerCommand* command);
        void setActiveCommandTab(ICommandTab* commandtab);
        void focusOn(QWidget* w);
        void showReferences(IDisassemblerCommand* command, rd_address address);
        void showGoto(IDisassemblerCommand* command);
        void showDeveloperTools();

    public:
        ICommandTab* activeCommandTab() const;
        IDisassemblerCommand* activeCommand() const;
        QWidget* currentTab() const;
        bool openDatabase(const QString& filepath);
        void enableCommands(QWidget* w);
        void updateCommandStates(QWidget* w) const;
        void statusAddress(const IDisassemblerCommand* command) const;
        void load(const QString& filepath);
        void tab(QWidget* w, int index = -1);
        void tabify(QDockWidget* first, QDockWidget* second);
        void dock(QWidget* w, Qt::DockWidgetArea area);
        void undock(QDockWidget* dw);

    private slots:
        void onToolBarActionTriggered(QAction* action);
        void onWindowActionTriggered(QAction* action);
        void adjustActions();

    private:
        template<typename T> ITableTab* findModelInTabs() const;
        ITableTab* findSymbolModelInTabs(rd_type type, rd_flag flags) const;
        static void listenEvents(const RDEventArgs* e);
        Q_INVOKABLE void updateViewWidgets(bool busy);
        Q_INVOKABLE void enableViewCommands(bool enable);
        Q_INVOKABLE void showMessage(const QString& title, const QString& msg, size_t icon);
        Q_INVOKABLE void close(bool showwelcome);
        TableTab* createTable(ListingItemModel* model, const QString& title);
        OutputDock* outputDock() const;
        void checkListingMode();
        void clearOutput();
        void enableMenu(QMenu* menu, bool enable);
        void loadDisassemblerView(RDDisassembler* disassembler);
        void showLoaders(const QString& filepath, RDBuffer* buffer);
        void addWelcomeTab();
        void loadRecents();
        void hook();

    private:
        QMainWindow* m_mainwindow{nullptr};
        QToolBar* m_toolbar{nullptr};
        QMenu *m_mnuwindow{nullptr};
        QLabel* m_lblstatusicon{nullptr};
        QPushButton *m_pbproblems{nullptr}, *m_pbrenderer;
        DisassemblerView* m_disassemblerview{nullptr};
        DisassemblerTabs* m_disassemblertabs{nullptr};
        DevDialog* m_devdialog{nullptr};
        mutable ICommandTab* m_activecommandtab{nullptr};
        QFileInfo m_fileinfo;
        std::future<void> m_worker;
        static DisassemblerHooks m_instance;
};

template<typename T>
ITableTab* DisassemblerHooks::findModelInTabs() const
{
    for(int i = 0; i < m_disassemblertabs->count(); i++)
    {
        auto* tabletab = dynamic_cast<ITableTab*>(m_disassemblertabs->widget(i));
        if(!tabletab) continue;

        if(dynamic_cast<T*>(tabletab->model())) return tabletab;
    }

    return nullptr;
}
