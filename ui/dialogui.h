#ifndef DIALOGUI_H
#define DIALOGUI_H

#include <QListView>
#include <QDialog>
#include <redasm/redasm_ui.h>
#include "models/checkeditemsmodel.h"

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
        void setText(const QString& s);
        void setItems(REDasm::UI::CheckList& items);

    private:
        void createList(QAbstractItemModel *model);
        void setCanAccept(bool b);

    private:
        Ui::DialogUI *ui;
};

#endif // DIALOGUI_H
