#include "outputwidget.h"

OutputWidget::OutputWidget(QWidget *parent) : QPlainTextEdit(parent)
{
    this->setWindowTitle("Output");
    this->setReadOnly(true);
    this->setUndoRedoEnabled(false);
    this->setLineWrapMode(OutputWidget::NoWrap);
}

QSize OutputWidget::sizeHint() const
{
    QFontMetrics fm = this->fontMetrics();
    return QSize(fm.height() * 4, fm.height() * 4);
}

void OutputWidget::log(const QString &s)
{
    this->insertPlainText(s + "\n");
    this->ensureCursorVisible();
}
