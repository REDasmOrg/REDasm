#pragma once

#include <QWidget>
#include "splititem.h"

class QVBoxLayout;

class SplitView : public QWidget
{
    Q_OBJECT

    public:
        explicit SplitView(QWidget *parent = nullptr);
        void createFirst();

    protected:
        virtual QWidget* createWidget() = 0;
        virtual void onItemSplit(const SplitItem* item, const SplitItem* newitem) const;
        virtual void onItemCreated(SplitItem* item) const;

    private:
        QVBoxLayout* m_layout;

    friend class SplitItem;
};

