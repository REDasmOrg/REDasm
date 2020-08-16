#pragma once

#include <QMainWindow>
#include <QPushButton>
#include <QLabel>

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

    public:
        explicit MainWindow(QWidget *parent = nullptr);
        ~MainWindow();

    protected:
        void closeEvent(QCloseEvent* e) override;
        void dragEnterEvent(QDragEnterEvent* e) override;
        void dragMoveEvent(QDragMoveEvent* e) override;
        void dropEvent(QDropEvent* e) override;

    private slots:
        void onSaveClicked();
        void onSaveAsClicked();
        void onSignaturesClicked();
        void onResetLayoutClicked();
        void showProblems();

    private:
        void initializeLibrary();
        void loadWindowState();
        void checkCommandLine();
        bool loadDatabase(const QString& filepath);
        bool canClose();

    private:
        Ui::MainWindow *ui;
        QLabel *m_lblstatus, *m_lblprogress, *m_lblstatusicon;
        QStringList m_recents;
        QPushButton *m_pbproblems, *m_pbrenderer;
};
