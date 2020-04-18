#include "disassembleractions.h"
#include "../convert.h"
#include <redasm/disassembler/disassembler.h>
#include <redasm/plugins/assembler/assembler.h>
#include <redasm/support/utils.h>
#include <redasm/context.h>
#include <QApplication>
#include <QInputDialog>
#include <QMessageBox>
#include <QClipboard>

DisassemblerActions::DisassemblerActions(QWidget *parent): QObject(parent) { this->createActions(); }
DisassemblerActions::DisassemblerActions(PainterRenderer* renderer, QWidget *parent) : QObject(parent), m_renderer(renderer) { this->createActions(); }
void DisassemblerActions::setCurrentRenderer(REDasm::ListingRenderer *renderer) { }
REDasm::ListingRenderer *DisassemblerActions::renderer() const { return nullptr; }
void DisassemblerActions::popup(const QPoint &pos) { if(m_renderer) m_contextmenu->exec(pos); }

void DisassemblerActions::adjustActions()
{
    // if(!m_renderer) return;

    // auto lock = REDasm::s_lock_safe_ptr(r_doc);
    // REDasm::ListingItem item = lock->currentItem();
    // if(!item.isValid()) return;

    // m_actions[DisassemblerActions::Action_Back]->setVisible(RDCursor_CanGoBack(m_renderer->cursor()));
    // m_actions[DisassemblerActions::Action_Forward]->setVisible(RDCursor_CanGoForward(m_renderer->cursor()));
    // m_actions[DisassemblerActions::Action_Copy]->setVisible(RDCursor_HasSelection(m_renderer->cursor()));
    // m_actions[DisassemblerActions::Action_Goto]->setVisible(!RD_IsBusy());
    // m_actions[DisassemblerActions::Action_ItemInformation]->setVisible(!RD_IsBusy());

    // const REDasm::Segment *itemsegment = lock->segment(item.address), *symbolsegment = nullptr;
    // RDSymbol symbol;

    // if(!m_renderer->selectedSymbol(&symbol))
    // {
    //     symbolsegment = lock->segment(item.address);
    //     //symbol = lock->functionStartSymbol(item.address);

    //     m_actions[DisassemblerActions::Action_Rename]->setVisible(false);
    //     m_actions[DisassemblerActions::Action_XRefs]->setVisible(false);
    //     m_actions[DisassemblerActions::Action_Follow]->setVisible(false);
    //     m_actions[DisassemblerActions::Action_FollowPointerHexDump]->setVisible(false);

    //     if(!r_disasm->busy())
    //     {
    //         bool ok = false;
    //         address_t currentaddress = m_renderer->currentWord().toUInt(&ok, 16);
    //         const REDasm::Segment* currentsegment = ok ? r_doc->segment(currentaddress) : nullptr;

    //         m_actions[DisassemblerActions::Action_CreateFunction]->setVisible(currentsegment && currentsegment->is(REDasm::Segment::T_Code));

    //         if(currentsegment)
    //             m_actions[DisassemblerActions::Action_CreateFunction]->setText(QString("Create Function @ %1").arg(Convert::to_qstring(REDasm::String::hex(currentaddress))));
    //     }
    //     else
    //         m_actions[DisassemblerActions::Action_CreateFunction]->setVisible(false);

    //     if(symbol)
    //         m_actions[DisassemblerActions::Action_CallGraph]->setText(QString("Callgraph %1").arg(Convert::to_qstring(symbol->name)));

    //     m_actions[DisassemblerActions::Action_CallGraph]->setVisible(symbol && symbolsegment && symbolsegment->is(REDasm::Segment::T_Code));
    //     m_actions[DisassemblerActions::Action_HexDumpFunction]->setVisible((symbol != nullptr));
    //     m_actions[DisassemblerActions::Action_HexDump]->setVisible(true);
    //     return;
    // }

    // symbolsegment = lock->segment(symbol->address);

    // m_actions[DisassemblerActions::Action_CreateFunction]->setText(QString("Create Function @ %1").arg(Convert::to_qstring(REDasm::String::hex(symbol->address))));
    // m_actions[DisassemblerActions::Action_CreateFunction]->setVisible(!r_disasm->busy() &&
    //                                                            (symbolsegment && symbolsegment->is(REDasm::Segment::T_Code)) &&
    //                                                            (symbol->isWeak() && !symbol->isFunction()));


    // m_actions[DisassemblerActions::Action_FollowPointerHexDump]->setText(QString("Follow %1 pointer in Hex Dump").arg(Convert::to_qstring(symbol->name)));
    // m_actions[DisassemblerActions::Action_FollowPointerHexDump]->setVisible(symbol->isPointer());

    // m_actions[DisassemblerActions::Action_XRefs]->setText(QString("Cross Reference %1").arg(Convert::to_qstring(symbol->name)));
    // m_actions[DisassemblerActions::Action_XRefs]->setVisible(!r_disasm->busy());

    // m_actions[DisassemblerActions::Action_Rename]->setText(QString("Rename %1").arg(Convert::to_qstring(symbol->name)));
    // m_actions[DisassemblerActions::Action_Rename]->setVisible(!r_disasm->busy() && symbol->isWeak());

    // m_actions[DisassemblerActions::Action_CallGraph]->setText(QString("Callgraph %1").arg(Convert::to_qstring(symbol->name)));
    // m_actions[DisassemblerActions::Action_CallGraph]->setVisible(!r_disasm->busy() && symbol->isFunction());

    // m_actions[DisassemblerActions::Action_Follow]->setText(QString("Follow %1").arg(Convert::to_qstring(symbol->name)));
    // m_actions[DisassemblerActions::Action_Follow]->setVisible(symbol->isLabel());

    // m_actions[DisassemblerActions::Action_Comment]->setVisible(!r_disasm->busy() && item.is(REDasm::ListingItem::InstructionItem));

    // m_actions[DisassemblerActions::Action_HexDump]->setVisible(symbolsegment && !symbolsegment->is(REDasm::Segment::T_Bss));
    // m_actions[DisassemblerActions::Action_HexDumpFunction]->setVisible(itemsegment && !itemsegment->is(REDasm::Segment::T_Bss) && itemsegment->is(REDasm::Segment::T_Code));
}

void DisassemblerActions::goTo(address_t address) { if(m_renderer) r_doc->goTo(address); }

void DisassemblerActions::createActions()
{
    QWidget* pw = this->widget();

    m_contextmenu = new QMenu(pw);
    m_actions[DisassemblerActions::Action_Rename] = m_contextmenu->addAction("Rename", this, &DisassemblerActions::renameSymbolUnderCursor, QKeySequence(Qt::Key_N));
    m_actions[DisassemblerActions::Action_Comment] = m_contextmenu->addAction("Comment", this, &DisassemblerActions::addComment, QKeySequence(Qt::Key_Semicolon));
    m_contextmenu->addSeparator();
    m_actions[DisassemblerActions::Action_XRefs] = m_contextmenu->addAction("Cross References", this, &DisassemblerActions::showReferencesUnderCursor, QKeySequence(Qt::Key_X));
    m_actions[DisassemblerActions::Action_Follow] = m_contextmenu->addAction("Follow", this, QOverload<>::of(&DisassemblerActions::followUnderCursor));
    m_actions[DisassemblerActions::Action_FollowPointerHexDump] = m_contextmenu->addAction("Follow pointer in Hex Dump", this, &DisassemblerActions::followPointerHexDump);
    m_actions[DisassemblerActions::Action_Goto] = m_contextmenu->addAction("Goto...", this, &DisassemblerActions::gotoDialogRequested, QKeySequence(Qt::Key_G));
    m_actions[DisassemblerActions::Action_CallGraph] = m_contextmenu->addAction("Call Graph", this, &DisassemblerActions::showCallGraph, QKeySequence(Qt::CTRL + Qt::Key_G));
    m_contextmenu->addSeparator();
    m_actions[DisassemblerActions::Action_HexDump] = m_contextmenu->addAction("Show Hex Dump", this, &DisassemblerActions::showHexDump, QKeySequence(Qt::CTRL + Qt::Key_H));
    m_actions[DisassemblerActions::Action_HexDumpFunction] = m_contextmenu->addAction("Hex Dump Function", this, &DisassemblerActions::printFunctionHexDump);
    m_actions[DisassemblerActions::Action_CreateFunction] = m_contextmenu->addAction("Create Function", this, &DisassemblerActions::createFunction, QKeySequence(Qt::SHIFT + Qt::Key_C));
    m_contextmenu->addSeparator();
    m_actions[DisassemblerActions::Action_Back] = m_contextmenu->addAction("Back", this, &DisassemblerActions::goBack, QKeySequence(Qt::CTRL + Qt::Key_Left));
    m_actions[DisassemblerActions::Action_Forward] = m_contextmenu->addAction("Forward", this, &DisassemblerActions::goForward, QKeySequence(Qt::CTRL + Qt::Key_Right));
    m_contextmenu->addSeparator();
    m_actions[DisassemblerActions::Action_Copy] = m_contextmenu->addAction("Copy", this, &DisassemblerActions::copy, QKeySequence(QKeySequence::Copy));
    m_actions[DisassemblerActions::Action_ItemInformation] = m_contextmenu->addAction("Item Information", this, &DisassemblerActions::itemInformationRequested);

    if(pw)
    {
        pw->addAction(m_actions[DisassemblerActions::Action_Rename]);
        pw->addAction(m_actions[DisassemblerActions::Action_XRefs]);
        pw->addAction(m_actions[DisassemblerActions::Action_Comment]);
        pw->addAction(m_actions[DisassemblerActions::Action_Goto]);
        pw->addAction(m_actions[DisassemblerActions::Action_CallGraph]);
        pw->addAction(m_actions[DisassemblerActions::Action_HexDump]);
        pw->addAction(m_actions[DisassemblerActions::Action_CreateFunction]);
        pw->addAction(m_actions[DisassemblerActions::Action_Back]);
        pw->addAction(m_actions[DisassemblerActions::Action_Forward]);
        pw->addAction(m_actions[DisassemblerActions::Action_Copy]);
    }

    connect(m_contextmenu, &QMenu::aboutToShow, this, &DisassemblerActions::adjustActions);
}

void DisassemblerActions::renameSymbolUnderCursor()
{
    // if(!m_renderer)
    //     return;

    // const REDasm::Symbol* symbol = m_renderer->symbolUnderCursor();
    // if(!symbol || !symbol->isWeak()) return;

    // QString symbolname = Convert::to_qstring(symbol->name);
    // QString res = QInputDialog::getText(this->widget(), QString("Rename %1").arg(symbolname), "Symbol name:", QLineEdit::Normal, symbolname);

    // if(r_doc->symbol(Convert::to_rstring(res)))
    // {
    //     QMessageBox::warning(this->widget(), "Rename failed", "Duplicate symbol name");
    //     this->renameSymbolUnderCursor();
    //     return;
    // }

    // r_doc->rename(symbol->address, Convert::to_rstring(res));
}

bool DisassemblerActions::followUnderCursor()
{
    // if(!m_renderer) return false;

    // const REDasm::Symbol* symbol = m_renderer->symbolUnderCursor();
    // if(symbol) r_doc->goTo(symbol->address); else return false;
    // return true;
}

void DisassemblerActions::setEnabled(bool b)
{
    for(QAction* a : m_actions) a->setEnabled(b);
}

void DisassemblerActions::showCallGraph()
{
    // const REDasm::Symbol* symbol = m_renderer->symbolUnderCursor();
    // if(!symbol) symbol = r_doc->functionStartSymbol(r_doc->currentItem().address);
    // if(symbol) emit callGraphRequested(symbol->address);
}

void DisassemblerActions::showHexDump()
{
    // const REDasm::Symbol* symbol = m_renderer->symbolUnderCursor();

    // if(!symbol)
    // {
    //     emit switchToHexDump();
    //     return;
    // }

    // u64 len = sizeof(r_asm->addressWidth());

    // if(symbol->isAsciiString()) len = r_disasm->readString(symbol).size();
    // else if(symbol->isWideString()) len = r_disasm->readWString(symbol).size();

    // emit hexDumpRequested(symbol->address, len);
}

void DisassemblerActions::showReferencesUnderCursor()
{
    // const REDasm::Symbol* symbol = m_renderer->symbolUnderCursor();
    // if(!symbol) return;

    // emit referencesRequested(symbol->address);
}

void DisassemblerActions::printFunctionHexDump()
{
    // const REDasm::Symbol* symbol = nullptr;
    // REDasm::String s = r_disasm->getHexDump(r_doc->currentItem().address, &symbol);
    // if(s.empty()) return;

    // r_ctx->log(symbol->name + ": " + s.quoted());
}

void DisassemblerActions::followPointerHexDump()
{
    // const REDasm::Symbol* symbol = m_renderer->symbolUnderCursor();
    // if(!symbol || !symbol->isPointer()) return;

    // u64 destination = 0;

    // if(!r_disasm->dereference(symbol->address, &destination) || !r_doc->segment(destination))
    //     return;

    // emit hexDumpRequested(destination, r_asm->addressWidth());
}

void DisassemblerActions::createFunction()
{
    // bool ok = false;
    // const REDasm::Symbol* symbol = m_renderer->symbolUnderCursor();
    // address_t address = symbol ? symbol->address : m_renderer->getCurrentWord().toUInt(16, &ok);

    // if(!symbol && !ok)
    // {
    //     r_ctx->log("Cannot disassemble " + m_renderer->getCurrentWord());
    //     return;
    // }

    // r_disasm->disassemble(address);
    // r_doc->function(address);
}

void DisassemblerActions::addComment()
{
    // REDasm::ListingItem currentitem =  r_doc->currentItem();

    // bool ok = false;
    // QString res = QInputDialog::getMultiLineText(this->widget(),
    //                                              "Comment @ " + Convert::to_qstring(REDasm::String::hex(currentitem.address)),
    //                                              "Insert a comment (leave blank to remove):",
    //                                              Convert::to_qstring(r_doc->comment(currentitem.address, true)), &ok);

    // if(!ok)
    //     return;

    // r_doc->comment(currentitem.address, Convert::to_rstring(res));
}

void DisassemblerActions::goForward() { RDCursor_GoForward(m_renderer->cursor()); }
void DisassemblerActions::goBack() { RDCursor_GoBack(m_renderer->cursor()); }

void DisassemblerActions::copy()
{
    if(!RDCursor_HasSelection(m_renderer->cursor())) return;
    qApp->clipboard()->setText(m_renderer->selectedText());
}

QWidget *DisassemblerActions::widget() const { return qobject_cast<QWidget*>(this->parent()); }
