#ifndef DISASSEMBLERVIEWACTIONS_H
#define DISASSEMBLERVIEWACTIONS_H

#include <QLinkedList>
#include <QToolBar>
#include <QHash>

class DisassemblerViewActions : public QObject
{
    Q_OBJECT

    public:
        enum { BackAction = 0, ForwardAction, GotoAction, GraphListingAction };

    public:
        explicit DisassemblerViewActions(QObject *parent = nullptr);
        void setIcon(int actionid, const QIcon& icon);
        void setEnabled(int actionid, bool b);
        void setVisible(int actionid, bool b);
        void hideActions();

    private:
        template<typename Func> void showAction(int type, QAction* action, const QIcon& icon, const Func& slot);
        void findActions(const std::function<void(QAction*)>& cb);
        void initActions();

    signals:
        void backRequested();
        void forwardRequested();
        void gotoRequested();
        void graphListingRequested();

    private:
        QToolBar* m_toolbar;
        QHash<int, QAction*> m_actions;
        QLinkedList<QAction*> m_separators;
};

template<typename Func> void DisassemblerViewActions::showAction(int type, QAction* action, const QIcon& icon, const Func& slot) {
    m_actions[type] = action;
    action->setIcon(icon);
    action->setVisible(true);
    connect(action, &QAction::triggered, this, slot);
}

#endif // DISASSEMBLERVIEWACTIONS_H
