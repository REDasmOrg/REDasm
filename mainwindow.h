#pragma once

#include <kddockwidgets/MainWindow.h>
#include <QPushButton>
#include <QLabel>

class MainWindow : public KDDockWidgets::MainWindow
{
    Q_OBJECT

    public:
        explicit MainWindow();
        ~MainWindow() = default;

    protected:
        void closeEvent(QCloseEvent* e) override;
        void dragEnterEvent(QDragEnterEvent* e) override;
        void dragMoveEvent(QDragMoveEvent* e) override;
        void dropEvent(QDropEvent* e) override;

    private Q_SLOTS:
        void onSaveClicked();
        void onSaveAsClicked();
        void onSignaturesClicked();
        void onResetLayoutClicked();

    private:
        void createFileMenu();
        void createREDasmMenu();
        void createWindowMenu();
        void createHelpMenu();
        void initializeConfig();
        void loadWindowState();
        void checkCommandLine();
        bool loadDatabase(const QString& filepath);
        bool canClose();

    private:
        QLabel *m_lblstatus, *m_lblprogress, *m_lblstatusicon;
        QStringList m_recents;
        QPushButton *m_pbproblems, *m_pbrenderer;
};
