#pragma once

#include <QFontMetrics>
#include <QMenu>
#include <rdapi/rdapi.h>
#include "../cursorscrollarea.h"
#include "../../hooks/idisassemblercommand.h"
#include "../../renderer/painterrenderer.h"
#include "../disassemblerpopup/disassemblerpopup.h"

class DisassemblerTextView : public CursorScrollArea, public IDisassemblerCommand
{
    Q_OBJECT

    public:
        explicit DisassemblerTextView(QWidget *parent = nullptr);
        virtual ~DisassemblerTextView();
        size_t visibleLines() const;
        size_t firstVisibleLine() const;
        size_t lastVisibleLine() const;
        void setDisassembler(RDDisassembler* disassembler);

    public: // IDisassemblerCommand interface
        void goBack() override;
        void goForward() override;
        bool gotoAddress(address_t address) override;
        bool gotoItem(const RDDocumentItem& item) override;
        bool hasSelection() const override;
        bool canGoBack() const override;
        bool canGoForward() const override;
        bool getCurrentItem(RDDocumentItem* item) const override;
        bool getSelectedSymbol(RDSymbol* symbol) const override;
        bool ownsCursor(const RDCursor* cursor) const override;
        const RDCursorPos* currentPosition() const override;
        const RDCursorPos* currentSelection() const override;
        QString currentWord() const override;
        RDDisassembler* disassembler() const override;
        RDCursor* cursor() const override;
        QWidget* widget() override;
        void copy() const override;

    private slots:
        void moveToSelection();

    protected:
        void onCursorBlink() override;
        void scrollContentsBy(int dx, int dy) override;
        void paintEvent(QPaintEvent* e) override;
        void resizeEvent(QResizeEvent* e) override;
        void mousePressEvent(QMouseEvent* e) override;
        void mouseMoveEvent(QMouseEvent* e) override;
        void mouseDoubleClickEvent(QMouseEvent* e) override;
        void wheelEvent(QWheelEvent *e) override;
        void keyPressEvent(QKeyEvent *e) override;
        bool event(QEvent* e) override;

    private:
        QRect lineRect(size_t line) const;
        QPointF viewportPoint(const QPointF& pt) const;
        void paintLine(size_t line);
        void paintLines(size_t first, size_t last);
        void onDocumentChanged(const RDEventArgs* e);
        bool followUnderCursor();
        bool isLineVisible(size_t line) const;
        bool isColumnVisible(size_t column, size_t* xpos);
        void adjustScrollBars();
        void ensureColumnVisible();
        void showPopup(const QPoint& pt);

    signals:
        void switchView();
        void canGoBackChanged();
        void canGoForwardChanged();
        void addressChanged(address_t address);

    private:
        QSet<event_t> m_events;
        std::unique_ptr<PainterRenderer> m_renderer;
        RDDisassembler* m_disassembler{nullptr};
        RDDocument* m_document{nullptr};

    private:
        DisassemblerPopup* m_disassemblerpopup{nullptr};
        QMenu* m_contextmenu{nullptr};
};
