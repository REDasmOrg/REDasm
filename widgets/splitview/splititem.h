#pragma once

#include <QToolBar>
#include <QWidget>

class QPushButton;
class SplitView;

class SplitItem : public QWidget
{
    Q_OBJECT

    public:
        explicit SplitItem(QWidget* w, SplitView* view, QWidget* parent = nullptr);
        QWidget* widget() const;
        QAction* action(int idx) const;
        QAction* addButton(const QIcon& icon);
        void setCanClose(bool b);

    private slots:
        void splitInDialog();
        void splitHorizontal();
        void splitVertical();
        void unsplit();

    private:
        void createDefaultButtons();
        void split(Qt::Orientation orientation);

    private:
        QWidget *m_widget, *m_container;
        SplitView* m_view;
        QAction* m_actclose;
        QToolBar* m_tbactions;
};

