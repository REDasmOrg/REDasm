#pragma once

#include <QPlainTextEdit>

class OutputWidget : public QPlainTextEdit
{
    Q_OBJECT

    public:
        explicit OutputWidget(QWidget *parent = nullptr);
        QSize sizeHint() const override;

    public Q_SLOTS:
        void log(const QString& s);
};
