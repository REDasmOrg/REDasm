#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QPushButton>
#include <QFileInfo>
#include <QLabel>
#include <redasm/plugins/plugins.h>
#include <redasm/disassembler/disassembler.h>
#include "widgets/disassemblerview/disassemblerview.h"

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
        void onResetLayoutClicked();
        void onSettingsClicked();
        void onAboutClicked();
        void changeDisassemblerStatus();
        void checkDisassemblerStatus();

    private:
        DisassemblerView* currentDisassemblerView() const;
        REDasm::DisassemblerAPI* currentDisassembler() const;
        void loadWindowState();
        void loadRecents();
        bool loadDatabase(const QString& filepath);
        void load(const QString &filepath);
        void checkCommandLine();
        bool checkPlugins(REDasm::AbstractBuffer* buffer, REDasm::FormatPlugin** format, REDasm::AssemblerPlugin** assembler);
        void showDisassemblerView(REDasm::Disassembler *disassembler);
        void initDisassembler(REDasm::AbstractBuffer *buffer);
        void setViewWidgetsVisible(bool b);
        void closeFile();
        bool canClose();

    private:
        Ui::MainWindow *ui;
        QLabel *m_lblstatus, *m_lblprogress;
        QFileInfo m_fileinfo;
        QStringList m_recents;
        QPushButton* m_pbstatus;
        REDasm::Disassembler* m_disassembler;
};

#endif // MAINWINDOW_H
