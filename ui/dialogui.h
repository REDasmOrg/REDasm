#pragma once

#include <QListView>
#include <QDialog>
//#include <redasm/ui.h>
#include "models/checkeditemsmodel.h"
#include "models/listitemsmodel.h"

namespace Ui {
class DialogUI;
}

class DialogUI : public QDialog
{
    Q_OBJECT

    public:
        explicit DialogUI(QWidget *parent = nullptr);
        ~DialogUI();

    public:
        int selectedIndex() const;
        void setText(const QString& s);
        //void selectableItems(const REDasm::List& items);
        //void setItems(REDasm::UI::CheckList& items);

    private:
        void hideFilter();
        void createList(QAbstractItemModel *model);
        void setCanAccept(bool b);

    private:
        Ui::DialogUI *ui;
        int m_selectedindex;
};
