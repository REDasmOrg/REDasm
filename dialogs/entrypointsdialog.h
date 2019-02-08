#ifndef ENTRYPOINTSDIALOG_H
#define ENTRYPOINTSDIALOG_H

#include <QDialog>
#include <redasm/disassembler/disassemblerapi.h>
#include "../models/symboltablemodel.h"
#include "../models/listingfiltermodel.h"

namespace Ui {
class EntryPointsDialog;
}

class EntryPointsDialog : public QDialog
{
    Q_OBJECT

    public:
        explicit EntryPointsDialog(REDasm::DisassemblerAPI* disassembler, QWidget *parent = NULL);
        ~EntryPointsDialog();

    private:
        Ui::EntryPointsDialog *ui;
        ListingFilterModel* m_entrypointsmodel;
};

#endif // ENTRYPOINTSDIALOG_H
