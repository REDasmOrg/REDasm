#pragma once

#define HOOK_TOOLBAR             "toolBar"
#define HOOK_STATUS_ICON         "lblStatusIcon"
#define HOOK_PROBLEMS            "pbProblems"
#define HOOK_RENDERER            "pbRenderer"
#define HOOK_MENU_WINDOW         "menu_Window"
#define HOOK_ACTION_SAVE_AS      "action_Save_As"
#define HOOK_ACTION_CLOSE        "action_Close"
#define HOOK_ACTION_RECENT_FILES "action_Recent_Files"
#define HOOK_ACTION_FLC          "action_FLC"
#define HOOK_ACTION_DEVTOOLS     "action_Developer_Tools"
#define HOOK_ACTION_DATABASE     "action_Database"

#include <kddockwidgets/MainWindow.h>
#include <kddockwidgets/DockWidget.h>
#include <QPushButton>
#include <QLabel>
#include <QFileInfo>
#include <rdapi/rdapi.h>
#include "isurface.h"

class FLCDialog;
class DevDialog;
class OutputWidget;
class DisassemblerDocks;
class DockWidget;

class DisassemblerHooks: public QObject
{
    Q_OBJECT

    private:
        DisassemblerHooks(QObject* parent = nullptr);

    public:
        static void initialize(KDDockWidgets::MainWindow* mainwindow);
        static DisassemblerHooks* instance();
        static KDDockWidgets::MainWindow* mainWindow();
        static DockWidget* dockify(QWidget* w, KDDockWidgets::DockWidget::Options options = KDDockWidgets::DockWidget::Options());
        static KDDockWidgets::DockWidget* tabify(QWidget* w, KDDockWidgets::DockWidget::Options options = KDDockWidgets::DockWidget::Options());
        static KDDockWidgets::DockWidget* tabify(DockWidget* dock);
        Q_INVOKABLE void enableViewCommands(bool enable);
        bool isLoaded() const;
        QAction* addWindowAction(DockWidget* dw);
        void removeWindowAction(QAction* a);
        void openHomePage() const;
        void openTwitter() const;
        void openTelegram() const;
        void openReddit() const;
        void openGitHub() const;

    public Q_SLOTS:
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
        void showFLC();
        void showCallGraph(rd_address address);
        void showDeveloperTools();
        void showDatabase();
        void showProblems();
        void showDialog(const QString& title, QWidget* w);

    public:
        Q_INVOKABLE void close(bool showwelcome);
        SurfaceQt* activeSurface() const;
        RDContextPtr activeContext() const;
        bool openDatabase(const QString& filepath);
        void enableCommands(QWidget* w);
        void statusAddress(const SurfaceQt* surface) const;
        void load(const QString& filepath);

    private:
        OutputWidget* outputWidget() const;
        void reshortcutWindow();
        void checkListingMode();
        void showOutput();
        void clearOutput();
        void enableMenu(QMenu* menu, bool enable);
        void loadDisassemblerDocks(const RDContextPtr& ctx);
        void showLoaders(const QString& filepath, RDBuffer* buffer);
        void setTabBarVisible(bool b);
        void showWelcome();
        void loadRecents();
        void hook();

    private:
        QList<QAction*> m_windowactions;
        KDDockWidgets::MainWindow* m_mainwindow{nullptr};
        KDDockWidgets::DockWidget* m_dockoutput{nullptr};
        QToolBar* m_toolbar{nullptr};
        QMenu* m_mnuwindow{nullptr};
        QLabel* m_lblstatusicon{nullptr};
        QPushButton *m_pbproblems{nullptr}, *m_pbrenderer{nullptr};
        DisassemblerDocks* m_disassemblerdocks{nullptr};
        DevDialog* m_devdialog{nullptr};
        FLCDialog* m_flcdialog{nullptr};
        QFileInfo m_fileinfo;
};
