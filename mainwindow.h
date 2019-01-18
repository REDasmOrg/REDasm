#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QPushButton>
#include <QFileInfo>
#include <QLabel>
#include <redasm/plugins/plugins.h>
#include <redasm/disassembler/disassembler.h>

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
        bool eventFilter(QObject* obj, QEvent* e);

    private slots:
        void onOpenClicked();
        void onSaveClicked();
        void onSaveAsClicked();
        void onCloseClicked();
        void onRecentFileClicked();
        void onExitClicked();
        void onImportSignatureClicked();
        void onSettingsClicked();
        void onAboutClicked();
        void checkCommandState();
        void log(const QString &s);

    private:
        void loadGeometry();
        void loadRecents();
        bool loadDatabase(const QString& filepath);
        void load(const QString &filepath);
        void checkCommandLine();
        bool checkPlugins(REDasm::Buffer &buffer, REDasm::FormatPlugin** format, REDasm::AssemblerPlugin** assembler);
        void showDisassemblerView(REDasm::Disassembler *disassembler);
        void initDisassembler(REDasm::Buffer &buffer);
        void closeFile();
        bool canClose();

    private:
        Ui::MainWindow *ui;
        QLabel *m_lblstatus, *m_lblprogress;
        QFileInfo m_fileinfo;
        QStringList m_recents;
        QPushButton* m_pbstatus;
        REDasm::Disassembler *m_disassembler;
};

#endif // MAINWINDOW_H
