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
        virtual ~DisassemblerViewActions();
        void setIcon(int actionid, const QIcon& icon);
        void setEnabled(int actionid, bool b);
        void setVisible(int actionid, bool b);

    private:
        void addSeparator();
        void addActions();
        void removeActions();

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

#endif // DISASSEMBLERVIEWACTIONS_H
