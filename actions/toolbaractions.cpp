#include "toolbaractions.h"
#include "../redasmsettings.h"
#include "../redasmfonts.h"
#include <redasm/context.h>
#include <QDesktopServices>
#include <QFileInfo>
#include <QDebug>
#include <QMenu>
#include <QUrl>

ToolBarActions::ToolBarActions(QMainWindow* mainwindow): QObject(mainwindow)
{
    m_toolbar = mainwindow->findChild<QToolBar*>("toolBar");
    m_toolbar->setStyleSheet("QToolBar { border: 0px }");

    this->createMenu();
    this->loadRecents();

    this->addLeftPart();
    this->addRightPart();
}

void ToolBarActions::setActionEnabled(size_t action, bool b) { m_actions[action]->setEnabled(b); }

void ToolBarActions::setStandardActionsEnabled(bool b)
{
    m_actions[ToolBarActions::Save]->setEnabled(b);
    m_actions[ToolBarActions::SaveAs]->setEnabled(b);
    m_actions[ToolBarActions::Signatures]->setEnabled(b);
    m_devmenu->setEnabled(r_disasm || b);
}

void ToolBarActions::setDisassemblerActionsEnabled(bool b)
{
    auto actions = m_toolbar->actions();

    for(int i = m_startidx; i < actions.size(); i++)
    {
        actions[i]->setEnabled(b);
        actions[i]->setVisible(b);
    }
}

QToolButton* ToolBarActions::createButton(const QChar& code, const QString& text, bool visible)
{
    QToolButton* tb = new QToolButton(m_toolbar);
    tb->setEnabled(visible);
    tb->setVisible(visible);

    if(text.isEmpty()) tb->setToolButtonStyle(Qt::ToolButtonIconOnly);
    else tb->setToolButtonStyle(Qt::ToolButtonTextBesideIcon);

    tb->setIcon(FA_ICON(code));
    tb->setText(text);
    return tb;
}

QLabel* ToolBarActions::createLabel(const QString& text) { return new QLabel(text, m_toolbar); }

void ToolBarActions::addLeftPart()
{
    m_toolbar->addAction(m_actions[ToolBarActions::Open]);
    m_toolbar->addAction(m_actions[ToolBarActions::Save]);
    m_toolbar->addAction(m_actions[ToolBarActions::Recents]);
    m_toolbar->addSeparator();

    m_startidx = m_toolbar->actions().size();

    m_toolbar->addWidget(this->createButton(0xf053, "Back", false, &ToolBarActions::back));
    m_toolbar->addWidget(this->createButton(0xf054, "Forward", false, &ToolBarActions::forward));
    m_toolbar->addWidget(this->createButton(0xf101, "Goto", false, &ToolBarActions::goTo));
}

void ToolBarActions::addRightPart()
{
    QWidget* spacer = new QWidget();
    spacer->setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    m_toolbar->addWidget(spacer);

    QToolButton* tb = this->createButton(0xf0c9);
    tb->setPopupMode(QToolButton::InstantPopup);
    tb->setMenu(m_popupmenu);
    m_toolbar->addWidget(tb);
}

void ToolBarActions::loadRecents()
{
    REDasmSettings settings;
    m_recents = settings.recentFiles();

    QAction* actrecents = m_actions[ToolBarActions::Recents];
    actrecents->setEnabled(!m_recents.empty());

    m_recentsmenu->clear();

    for(int i = 0; i < MAX_RECENT_FILES; i++)
    {
        if(i >= m_recents.length())
        {
            QAction* action = m_recentsmenu->addAction(QString());
            action->setVisible(false);
            continue;
        }

        if(!QFileInfo(m_recents[i]).exists())
            continue;

        QAction* action = m_recentsmenu->addAction(QString("%1 - %2").arg(i).arg(m_recents[i]));
        action->setData(m_recents[i]);
        connect(action, &QAction::triggered, this, [=]() { emit loadRecent(action->data().toString()); });
    }}

void ToolBarActions::createAction(const QChar& code, const QString& text, bool visible)
{
    QToolButton* tb = this->createButton(code, text, visible);
    QAction* a = m_toolbar->addWidget(tb);

    if(!text.isEmpty()) a->setObjectName(QString("action_%1").arg(text));
}

void ToolBarActions::createMenu()
{
    m_recentsmenu = new QMenu("Recent Files", m_toolbar);
    m_recentsmenu->setIcon(FA_ICON(0xf1da));

    m_windowmenu = new QMenu("Window", m_toolbar);

    m_communitymenu = new QMenu("Community", m_toolbar);
    m_communitymenu->addAction(FA_BRAND(0xf3fe), "Telegram", this, []() { QDesktopServices::openUrl(QUrl("https://t.me/REDasmDisassembler")); });
    m_communitymenu->addAction(FA_BRAND(0xf281), "Reddit", this, []() { QDesktopServices::openUrl(QUrl("https://www.reddit.com/r/REDasm")); });

    m_actions[ToolBarActions::ResetLayout] = m_windowmenu->addAction("Reset Layout", this, &ToolBarActions::resetLayout);

    m_devmenu = new QMenu("Development");
    m_actions[ToolBarActions::Blocks] = m_devmenu->addAction("Blocks", this, &ToolBarActions::blocks, QKeySequence(Qt::CTRL + Qt::SHIFT + Qt::Key_F1));
    m_actions[ToolBarActions::FunctionGraphs] = m_devmenu->addAction("Function Graphs", this, &ToolBarActions::functionGraphs, QKeySequence(Qt::CTRL + Qt::SHIFT + Qt::Key_F2));

    m_popupmenu = new QMenu(m_toolbar);
    m_actions[ToolBarActions::Open] = m_popupmenu->addAction(FA_ICON(0xf07c), "Open", this, &ToolBarActions::open, QKeySequence(Qt::CTRL + Qt::Key_O));
    m_actions[ToolBarActions::Save] = m_popupmenu->addAction(FA_ICON(0xf0c7), "Save", this, &ToolBarActions::save, QKeySequence(Qt::CTRL + Qt::Key_S));
    m_actions[ToolBarActions::SaveAs] = m_popupmenu->addAction("Save As...", this, &ToolBarActions::saveAs, QKeySequence(Qt::CTRL + Qt::SHIFT + Qt::Key_S));
    m_actions[ToolBarActions::Close] = m_popupmenu->addAction("Close", this, &ToolBarActions::close);
    m_actions[ToolBarActions::Recents] = m_popupmenu->addMenu(m_recentsmenu);
    m_popupmenu->addSeparator();
    m_actions[ToolBarActions::Signatures] = m_popupmenu->addAction("Signatures", this, &ToolBarActions::signatures);
    m_actions[ToolBarActions::Development] = m_popupmenu->addMenu(m_devmenu);
    m_popupmenu->addSeparator();
    m_actions[ToolBarActions::Window] = m_popupmenu->addMenu(m_windowmenu);
    m_actions[ToolBarActions::Settings] = m_popupmenu->addAction("Settings", this, &ToolBarActions::settings);
    m_popupmenu->addSeparator();
    m_actions[ToolBarActions::Community] = m_popupmenu->addMenu(m_communitymenu);

    m_actions[ToolBarActions::Bug] = m_popupmenu->addAction("Report a Bug", this, []() {
        QDesktopServices::openUrl(QUrl("https://github.com/REDasmOrg/REDasm/issues"));
    });

    m_popupmenu->addSeparator();
    m_actions[ToolBarActions::Community] = m_popupmenu->addMenu(m_communitymenu);
    m_actions[ToolBarActions::About] = m_popupmenu->addAction("About", this, &ToolBarActions::about);
    m_actions[ToolBarActions::Exit] = m_popupmenu->addAction("Exit", this, &ToolBarActions::exit);
}
