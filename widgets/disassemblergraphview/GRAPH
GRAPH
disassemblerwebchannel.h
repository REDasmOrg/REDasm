#ifndef GRAPHWEBCHANNEL_H
#define GRAPHWEBCHANNEL_H

#include <QObject>

class GraphWebChannel : public QObject
{
    Q_OBJECT
public:
    explicit GraphWebChannel(QObject *parent = nullptr);

signals:

public slots:
};

#endif // GRAPHWEBCHANNEL_H