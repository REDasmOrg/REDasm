#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QPushButton>
#include <QLabel>
#include "redasm/plugins/plugins.h"

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

    public:
        explicit MainWindow(QWidget *parent = 0);
        ~MainWindow();

    protected:
        virtual void closeEvent(QCloseEvent* e);
        virtual void dragEnterEvent(QDragEnterEvent* e);
        virtual void dragMoveEvent(QDragMoveEvent* e);
        virtual void dropEvent(QDropEvent* e);

    private slots:
        void onOpenClicked();
        void onSettingsClicked();
        void onDatabaseClicked();
        void onAboutClicked();

    private:
        void loadGeometry();
        void applyTheme();
        void load(const QString &s);
        void checkCommandLine();
        bool checkPlugins(const REDasm::Buffer &buffer, REDasm::FormatPlugin **format, REDasm::AssemblerPlugin ** assembler);
        void initDisassembler();

    private:
        Ui::MainWindow *ui;
        QPushButton* m_pbstatus;
        QLabel* m_lblstatus;
        QByteArray m_loadeddata;
};

#endif // MAINWINDOW_H
