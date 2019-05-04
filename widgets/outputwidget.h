#ifndef OUTPUTWIDGET_H
#define OUTPUTWIDGET_H

#include <QPlainTextEdit>

class OutputWidget : public QPlainTextEdit
{
    Q_OBJECT

    public:
        explicit OutputWidget(QWidget *parent = nullptr);
        QSize sizeHint() const override;

    public slots:
        void log(const QString& s);
};

#endif // OUTPUTWIDGET_H
