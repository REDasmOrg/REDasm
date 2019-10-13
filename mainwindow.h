#pragma once

#include <QMainWindow>
#include <QPushButton>
#include <QFileInfo>
#include <QLabel>
#include <redasm/support/utils.h>
#include <redasm/redasm.h>
#include "widgets/disassemblerview/disassemblerview.h"
#include "dialogs/loaderdialog/loaderdialog.h"

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
        void closeEvent(QCloseEvent* e) override;
        void dragEnterEvent(QDragEnterEvent* e) override;
        void dragMoveEvent(QDragMoveEvent* e) override;
        void dropEvent(QDropEvent* e) override;
        bool eventFilter(QObject* obj, QEvent* e) override;

    private slots:
        void onOpenClicked();
        void onSaveClicked();
        void onSaveAsClicked();
        void onRecentFileClicked();
        void onExitClicked();
        void onSignaturesClicked();
        void onResetLayoutClicked();
        void onSettingsClicked();
        void onAboutClicked();
        void changeDisassemblerStatus();
        void checkDisassemblerStatus();
        void showProblems();
        void closeFile();

    private:
        DisassemblerView* currentDisassemblerView() const;
        REDasm::Disassembler* currentDisassembler() const;
        void loadWindowState();
        void loadRecents();
        bool loadDatabase(const QString& filepath);
        void load(const QString &filepath);
        void checkCommandLine();
        void setStandardActionsEnabled(bool b);
        void showDisassemblerView(REDasm::Disassembler *disassembler);
        void selectLoader(const REDasm::LoadRequest &request);
        void setViewWidgetsVisible(bool b);
        void configureWebEngine();
        bool canClose();

    private:
        Ui::MainWindow *ui;
        QLabel *m_lblstatus, *m_lblprogress;
        QFileInfo m_fileinfo;
        QStringList m_recents;
        QPushButton* m_pbstatus;
        QPushButton* m_pbproblems;
};
