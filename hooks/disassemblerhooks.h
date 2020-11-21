#pragma once

#define HOOK_TOOLBAR             "toolBar"
#define HOOK_STATUS_ICON         "lblStatusIcon"
#define HOOK_PROBLEMS            "pbProblems"
#define HOOK_RENDERER            "pbRenderer"
#define HOOK_MENU_WINDOW         "menu_Window"
#define HOOK_ACTION_SAVE_AS      "action_Save_As"
#define HOOK_ACTION_CLOSE        "action_Close"
#define HOOK_ACTION_RECENT_FILES "action_Recent_Files"
#define HOOK_ACTION_DEVTOOLS     "action_Developer_Tools"
#define HOOK_ACTION_DATABASE     "action_Database"

#include <QMainWindow>
#include <QPushButton>
#include <QLabel>
#include <QFileInfo>
#include <rdapi/rdapi.h>
#include "isurface.h"
#include "itabletab.h"

class DevDialog;
class OutputDock;
class DisassemblerView;
class ListingItemModel;
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

    public:
        static void initialize(QMainWindow* mainwindow);
        static DisassemblerHooks* instance();
        QMainWindow* mainWindow() const;
        Q_INVOKABLE void enableViewCommands(bool enable);

    public slots:
        void showMessage(const QString& title, const QString& msg, size_t icon);
        void updateViewWidgets(bool busy);
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
        void showDeveloperTools();
        void showDatabase();
        void showProblems();
        void focusOn(QWidget* w);

    public:
        SurfaceQt* activeSurface() const;
        RDContextPtr activeContext() const;
        bool openDatabase(const QString& filepath);
        void enableCommands(QWidget* w);
        void statusAddress(const SurfaceQt* surface) const;
        void load(const QString& filepath);

    private slots:
        void onWindowActionTriggered(QAction* action);

    private:
        Q_INVOKABLE void close(bool showwelcome);
        void dock(QWidget* w, Qt::DockWidgetArea area);
        void undock(QDockWidget* dw);
        void replaceWidget(QWidget* w);
        OutputDock* outputDock() const;
        void checkListingMode();
        void clearOutput();
        void enableMenu(QMenu* menu, bool enable);
        void loadDisassemblerView(const RDContextPtr& ctx);
        void showLoaders(const QString& filepath, RDBuffer* buffer);
        void showWelcome();
        void loadRecents();
        void hook();

    private:
        QMainWindow* m_mainwindow{nullptr};
        QToolBar* m_toolbar{nullptr};
        QMenu *m_mnuwindow{nullptr};
        QLabel* m_lblstatusicon{nullptr};
        QPushButton *m_pbproblems{nullptr}, *m_pbrenderer;
        DisassemblerView* m_disassemblerview{nullptr};
        DevDialog* m_devdialog{nullptr};
        QFileInfo m_fileinfo;
        static DisassemblerHooks m_instance;
};
