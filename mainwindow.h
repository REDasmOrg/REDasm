#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
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
        virtual void dragEnterEvent(QDragEnterEvent* e);
        virtual void dragMoveEvent(QDragMoveEvent* e);
        virtual void dropEvent(QDropEvent* e);

    private slots:
        void on_tbOpen_clicked();
        void on_tbDatabase_clicked();
        void on_tbAbout_clicked();

    private:
        void centerWindow();
        void applyTheme();
        void load(const QString &s);
        bool checkPlugins(REDasm::FormatPlugin **format, REDasm::ProcessorPlugin **processor);
        void initDisassembler();

    private:
        Ui::MainWindow *ui;
        QLabel* _lblstatus;
        QByteArray _loadeddata;
};

#endif // MAINWINDOW_H
