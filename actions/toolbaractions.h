#pragma once

#include <QMainWindow>
#include <QToolButton>
#include <QToolBar>
#include <QLabel>

class ToolBarActions: public QObject
{
    Q_OBJECT

    public:
        enum {
            Open, Save, SaveAs, Close, Recents,
            Signatures,
            Development, Blocks,
            Settings,
            Window, ResetLayout,
            Bug, Community, About, Exit
        };

    public:
        ToolBarActions(QMainWindow* mainwindow);
        void setActionEnabled(size_t action, bool b);
        void setStandardActionsEnabled(bool b);
        void loadRecents();

    private:
        void createAction(const QChar& code, const QString& text = QString(), bool visible = true);
        QToolButton* createButton(const QChar& code, const QString& text = QString(), bool visible = true);
        template<typename Slot> QToolButton* createButton(const QChar& code, const QString& text, const Slot& slot);
        QLabel* createLabel(const QString& text);
        void addLeftPart();
        void addRightPart();
        void createMenu();

    signals: // ToolBar
        void back();
        void forward();
        void goTo();
        void graphListing();

    signals: // Menu
        void loadRecent(const QString& filepath);
        void open();
        void save();
        void saveAs();
        void close();
        void exit();
        void signatures();
        void resetLayout();
        void settings();
        void blocks();
        void about();

    private:
        QHash<size_t, QAction*> m_actions;
        QStringList m_recents;
        QToolBar* m_toolbar;
        QMenu *m_popupmenu, *m_recentsmenu, *m_windowmenu, *m_communitymenu, *m_devmenu;
};

template<typename Slot>
QToolButton* ToolBarActions::createButton(const QChar& code, const QString& text, const Slot& slot)
{
    QToolButton* btn = this->createButton(code, text);
    connect(btn, &QToolButton::clicked, this, slot);
    return btn;
}

