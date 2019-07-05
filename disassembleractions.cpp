#include "disassembleractions.h"
#include "../convert.h"
#include <redasm/disassembler/disassembler.h>
#include <redasm/disassembler/listing/listingdocument.h>
#include <redasm/plugins/assembler/assembler.h>
#include <redasm/support/utils.h>
#include <redasm/context.h>
#include <QApplication>
#include <QInputDialog>
#include <QMessageBox>
#include <QClipboard>

DisassemblerActions::DisassemblerActions(QWidget *parent): QObject(parent), m_renderer(nullptr) { this->createActions(); }
DisassemblerActions::DisassemblerActions(REDasm::ListingRenderer* renderer, QWidget *parent) : QObject(parent), m_renderer(renderer) { this->createActions(); }
void DisassemblerActions::setCurrentRenderer(REDasm::ListingRenderer *renderer) { m_renderer = renderer; }
REDasm::ListingRenderer *DisassemblerActions::renderer() const { return m_renderer; }
void DisassemblerActions::popup(const QPoint &pos) { if(m_renderer) m_contextmenu->exec(pos); }

void DisassemblerActions::adjustActions()
{
    if(!m_renderer)
        return;

    auto lock = REDasm::s_lock_safe_ptr(m_renderer->document());
    const REDasm::ListingItem* item = lock->currentItem();

    if(!item)
        return;

    const REDasm::Symbol* symbol = m_renderer->symbolUnderCursor();
    REDasm::Segment *itemsegment = lock->segment(item->address()), *symbolsegment = nullptr;
    m_actions[DisassemblerActions::Back]->setVisible(lock->cursor()->canGoBack());
    m_actions[DisassemblerActions::Forward]->setVisible(lock->cursor()->canGoForward());
    m_actions[DisassemblerActions::Copy]->setVisible(lock->cursor()->hasSelection());
    m_actions[DisassemblerActions::Goto]->setVisible(!m_renderer->disassembler()->busy());
    m_actions[DisassemblerActions::ItemInformation]->setVisible(!m_renderer->disassembler()->busy());

    if(!symbol)
    {
        symbolsegment = lock->segment(item->address());
        symbol = lock->functionStartSymbol(item->address());

        m_actions[DisassemblerActions::Rename]->setVisible(false);
        m_actions[DisassemblerActions::XRefs]->setVisible(false);
        m_actions[DisassemblerActions::Follow]->setVisible(false);
        m_actions[DisassemblerActions::FollowPointerHexDump]->setVisible(false);

        if(symbol)
            m_actions[DisassemblerActions::CallGraph]->setText(QString("Callgraph %1").arg(Convert::to_qstring(symbol->name)));

        m_actions[DisassemblerActions::CallGraph]->setVisible(symbol && symbolsegment && symbolsegment->is(REDasm::SegmentType::Code));
        m_actions[DisassemblerActions::HexDumpFunction]->setVisible((symbol != nullptr));
        m_actions[DisassemblerActions::HexDump]->setVisible(true);
        return;
    }

    symbolsegment = lock->segment(symbol->address);

    m_actions[DisassemblerActions::FollowPointerHexDump]->setVisible(symbol->is(REDasm::SymbolType::Pointer));
    m_actions[DisassemblerActions::FollowPointerHexDump]->setText(QString("Follow %1 pointer in Hex Dump").arg(Convert::to_qstring(symbol->name)));

    m_actions[DisassemblerActions::XRefs]->setText(QString("Cross Reference %1").arg(Convert::to_qstring(symbol->name)));
    m_actions[DisassemblerActions::XRefs]->setVisible(!m_renderer->disassembler()->busy());

    m_actions[DisassemblerActions::Rename]->setText(QString("Rename %1").arg(Convert::to_qstring(symbol->name)));
    m_actions[DisassemblerActions::Rename]->setVisible(!m_renderer->disassembler()->busy() && !symbol->isLocked());

    m_actions[DisassemblerActions::CallGraph]->setVisible(!m_renderer->disassembler()->busy() && symbol->isFunction());
    m_actions[DisassemblerActions::CallGraph]->setText(QString("Callgraph %1").arg(Convert::to_qstring(symbol->name)));

    m_actions[DisassemblerActions::Follow]->setText(QString("Follow %1").arg(Convert::to_qstring(symbol->name)));
    m_actions[DisassemblerActions::Follow]->setVisible(symbol->is(REDasm::SymbolType::Code));

    m_actions[DisassemblerActions::Comment]->setVisible(!m_renderer->disassembler()->busy() && item->is(REDasm::ListingItemType::InstructionItem));

    m_actions[DisassemblerActions::HexDump]->setVisible(symbolsegment && !symbolsegment->is(REDasm::SegmentType::Bss));
    m_actions[DisassemblerActions::HexDumpFunction]->setVisible(itemsegment && !itemsegment->is(REDasm::SegmentType::Bss) && itemsegment->is(REDasm::SegmentType::Code));
}

void DisassemblerActions::goTo(address_t address) { if(m_renderer) m_renderer->document()->goTo(address); }

void DisassemblerActions::createActions()
{
    QWidget* pw = this->widget();

    m_contextmenu = new QMenu(pw);
    m_actions[DisassemblerActions::Rename] = m_contextmenu->addAction("Rename", this, &DisassemblerActions::renameSymbolUnderCursor, QKeySequence(Qt::Key_N));
    m_actions[DisassemblerActions::Comment] = m_contextmenu->addAction("Comment", this, &DisassemblerActions::addComment, QKeySequence(Qt::Key_Semicolon));
    m_contextmenu->addSeparator();
    m_actions[DisassemblerActions::XRefs] = m_contextmenu->addAction("Cross References", this, &DisassemblerActions::showReferencesUnderCursor, QKeySequence(Qt::Key_X));
    m_actions[DisassemblerActions::Follow] = m_contextmenu->addAction("Follow", this, QOverload<>::of(&DisassemblerActions::followUnderCursor));
    m_actions[DisassemblerActions::FollowPointerHexDump] = m_contextmenu->addAction("Follow pointer in Hex Dump", this, &DisassemblerActions::followPointerHexDump);
    m_actions[DisassemblerActions::Goto] = m_contextmenu->addAction("Goto...", this, &DisassemblerActions::gotoDialogRequested, QKeySequence(Qt::Key_G));
    m_actions[DisassemblerActions::CallGraph] = m_contextmenu->addAction("Call Graph", this, &DisassemblerActions::showCallGraph, QKeySequence(Qt::CTRL + Qt::Key_G));
    m_contextmenu->addSeparator();
    m_actions[DisassemblerActions::HexDump] = m_contextmenu->addAction("Show Hex Dump", this, &DisassemblerActions::showHexDump, QKeySequence(Qt::CTRL + Qt::Key_H));
    m_actions[DisassemblerActions::HexDumpFunction] = m_contextmenu->addAction("Hex Dump Function", this, &DisassemblerActions::printFunctionHexDump);
    m_contextmenu->addSeparator();
    m_actions[DisassemblerActions::Back] = m_contextmenu->addAction("Back", this, &DisassemblerActions::goBack, QKeySequence(Qt::CTRL + Qt::Key_Left));
    m_actions[DisassemblerActions::Forward] = m_contextmenu->addAction("Forward", this, &DisassemblerActions::goForward, QKeySequence(Qt::CTRL + Qt::Key_Right));
    m_contextmenu->addSeparator();
    m_actions[DisassemblerActions::Copy] = m_contextmenu->addAction("Copy", this, &DisassemblerActions::copy, QKeySequence(QKeySequence::Copy));
    m_actions[DisassemblerActions::ItemInformation] = m_contextmenu->addAction("Item Information", this, &DisassemblerActions::itemInformationRequested);

    if(pw)
    {
        pw->addAction(m_actions[DisassemblerActions::Rename]);
        pw->addAction(m_actions[DisassemblerActions::XRefs]);
        pw->addAction(m_actions[DisassemblerActions::Comment]);
        pw->addAction(m_actions[DisassemblerActions::Goto]);
        pw->addAction(m_actions[DisassemblerActions::CallGraph]);
        pw->addAction(m_actions[DisassemblerActions::HexDump]);
        pw->addAction(m_actions[DisassemblerActions::Back]);
        pw->addAction(m_actions[DisassemblerActions::Forward]);
        pw->addAction(m_actions[DisassemblerActions::Copy]);
    }

    connect(m_contextmenu, &QMenu::aboutToShow, this, &DisassemblerActions::adjustActions);
}

void DisassemblerActions::renameSymbolUnderCursor()
{
    if(!m_renderer)
        return;

    const REDasm::Symbol* symbol = m_renderer->symbolUnderCursor();

    if(!symbol || symbol->isLocked())
        return;

    QString symbolname = Convert::to_qstring(symbol->name);
    QString res = QInputDialog::getText(this->widget(), QString("Rename %1").arg(symbolname), "Symbol name:", QLineEdit::Normal, symbolname);

    if(m_renderer->document()->symbol(Convert::to_rstring(res)))
    {
        QMessageBox::warning(this->widget(), "Rename failed", "Duplicate symbol name");
        this->renameSymbolUnderCursor();
        return;
    }

    m_renderer->document()->rename(symbol->address, Convert::to_rstring(res));
}

bool DisassemblerActions::followUnderCursor()
{
    if(!m_renderer)
        return false;

    const REDasm::Symbol* symbol = m_renderer->symbolUnderCursor();

    if(symbol)
        m_renderer->document()->goTo(symbol->address);
    else
        return false;

    return true;
}

void DisassemblerActions::setEnabled(bool b)
{
    for(QAction* a : m_actions)
        a->setEnabled(a);
}

void DisassemblerActions::showCallGraph()
{
    const REDasm::Symbol* symbol = m_renderer->symbolUnderCursor();

    if(!symbol)
    {
        REDasm::ListingDocument& document = m_renderer->document();
        const REDasm::ListingItem* item = document->currentItem();
        symbol = document->functionStartSymbol(item->address());
    }

    if(symbol)
        emit callGraphRequested(symbol->address);
}

void DisassemblerActions::showHexDump()
{
    const REDasm::Symbol* symbol = m_renderer->symbolUnderCursor();

    if(!symbol)
    {
        emit switchToHexDump();
        return;
    }

    u64 len = sizeof(m_renderer->disassembler()->assembler()->addressWidth());

    if(symbol->is(REDasm::SymbolType::String))
        len = m_renderer->disassembler()->readString(symbol).size();

    emit hexDumpRequested(symbol->address, len);
}

void DisassemblerActions::showReferencesUnderCursor()
{
    const REDasm::Symbol* symbol = m_renderer->symbolUnderCursor();

    if(!symbol)
        return;

    emit referencesRequested(symbol->address);
}

void DisassemblerActions::printFunctionHexDump()
{
    const REDasm::Symbol* symbol = nullptr;
    REDasm::String s = m_renderer->disassembler()->getHexDump(m_renderer->document()->currentItem()->address(), &symbol);

    if(s.empty())
        return;

    r_ctx->log(symbol->name + ": " + s.quoted());
}

void DisassemblerActions::followPointerHexDump()
{
    const REDasm::Symbol* symbol = m_renderer->symbolUnderCursor();

    if(!symbol || !symbol->is(REDasm::SymbolType::Pointer))
        return;

    u64 destination = 0;

    if(!m_renderer->disassembler()->dereference(symbol->address, &destination) || !m_renderer->document()->segment(destination))
        return;

    emit hexDumpRequested(destination, m_renderer->disassembler()->assembler()->addressWidth());
}

void DisassemblerActions::addComment()
{
    const REDasm::ListingItem* currentitem =  m_renderer->document()->currentItem();

    m_renderer->document()->comment(currentitem, true);

    bool ok = false;
    QString res = QInputDialog::getMultiLineText(this->widget(),
                                                 "Comment @ " + Convert::to_qstring(REDasm::String::hex(currentitem->address())),
                                                 "Insert a comment (leave blank to remove):",
                                                 Convert::to_qstring(m_renderer->document()->comment(currentitem, true)), &ok);

    if(!ok)
        return;

    m_renderer->document()->comment(currentitem, Convert::to_rstring(res));
}

void DisassemblerActions::goForward() { m_renderer->document()->cursor()->goForward(); }
void DisassemblerActions::goBack() { m_renderer->document()->cursor()->goBack(); }

void DisassemblerActions::copy()
{
    if(!m_renderer->document()->cursor()->hasSelection())
        return;

    qApp->clipboard()->setText(Convert::to_qstring(m_renderer->getSelectedText()));
}

QWidget *DisassemblerActions::widget() const { return qobject_cast<QWidget*>(this->parent()); }
