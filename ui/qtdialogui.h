#pragma once

#include <QListView>
#include <QDialog>
#include <rdapi/rdapi.h>
#include "models/checkeditemsmodel.h"

namespace Ui {
class QtDialogUI;
}

class QtDialogUI : public QDialog
{
    Q_OBJECT

    public:
        explicit QtDialogUI(QWidget *parent = nullptr);
        ~QtDialogUI();

    public:
        int selectedIndex() const;
        void setText(const QString& s);
        void setCheckedOptions(RDUIOptions* options, size_t c);

    private:
        void hideFilter();
        void createList(QAbstractItemModel *model);
        void setCanAccept(bool b);

    private:
        Ui::QtDialogUI *ui;
        int m_selectedindex{-1};
};
