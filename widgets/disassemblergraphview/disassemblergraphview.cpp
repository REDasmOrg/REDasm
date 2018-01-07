#include "disassemblergraphview.h"

#define SCALE_FACTOR     1.5

#define SCENE_MARGIN     -20
#define PI               3.14
#define ARROW_SIZE       12

DisassemblerGraphView::DisassemblerGraphView(QWidget *parent) : QGraphicsView(parent)
{
    this->_scene = new QGraphicsScene(this);
    this->setScene(this->_scene);

    this->setMouseTracking(true);
    this->setDragMode(DisassemblerGraphView::ScrollHandDrag);
    this->setRenderHint(QPainter::Antialiasing);
}

void DisassemblerGraphView::setDisassembler(REDasm::Disassembler *disassembler)
{
    this->_disassembler = disassembler;
}

void DisassemblerGraphView::display(address_t address)
{
    if(!this->_disassembler)
        return;

    //REDasm::Listing& listing = this->_disassembler->listing();
    //REDasm::GraphBuilder gb(listing);

    //gb.build(address);
    this->scale(1.0, 1.0); // Reset zoom
    //this->renderGraph(gb);
}

void DisassemblerGraphView::wheelEvent(QWheelEvent *event)
{
    QGraphicsView::wheelEvent(event);

    if(!(event->modifiers() & Qt::ControlModifier))
        return;

    this->setTransformationAnchor(DisassemblerGraphView::AnchorUnderMouse);

    if(event->delta() > 0) // Zoom in
        this->scale(SCALE_FACTOR, SCALE_FACTOR);
    else // Zoom out
        this->scale(1.0 / SCALE_FACTOR, 1.0 / SCALE_FACTOR);
}

/*
void DisassemblerGraphView::renderGraph(REDasm::GraphBuilder &gb)
{
    NodeLookup items;
    REDasm::Listing& listing = this->_disassembler->listing();

    gb.iterateBlocks([this, &items, &listing](REDasm::GraphBuilder::Node* node, const REDasm::GraphBuilder::Block& block, double& width, double& height) {
        FunctionBlockItem* fbi = new FunctionBlockItem(this->_disassembler, "light");

        for(auto it = block.begin(); it != block.end(); it++)
            fbi->append(listing[*it]);

        QRectF r = fbi->boundingRect();
        width = r.width();
        height = r.height();

        items[node] = fbi;
    });

    gb.layout();
    this->_scene->clear();

    std::for_each(items.begin(), items.end(), [this, gb](const std::pair<REDasm::GraphBuilder::Node*, FunctionBlockItem*>& item) {
        double x = 0, y = 0;
        gb.position(item.first, x, y);
        item.second->setPos(this->scenePoint(item.second, x, y));
        this->_scene->addItem(item.second);
    });

    const REDasm::GraphBuilder::Edges& edges = gb.edges();

    std::for_each(edges.begin(), edges.end(), [this, &gb](REDasm::GraphBuilder::Edge* edge) {
        this->drawArrow(edge, gb);
    });

    //this->fitInView(this->_scene->itemsBoundingRect(), Qt::KeepAspectRatio);
}
*/

/*
void DisassemblerGraphView::drawArrow(REDasm::GraphBuilder::Edge* edge, REDasm::GraphBuilder& gb)
{
    ogdf::GraphAttributes& ga = gb.graphAttributes();
    ogdf::DPolyline& points = ga.bends(edge);

    if(points.empty())
    {
        this->drawArrow(this->bottomCenter(gb, edge->source()),
                        this->topCenter(gb, edge->target()),
                        QColor(QString::fromStdString(ga.strokeColor(edge).toString())));

        return;
    }

    QPainterPath path(this->bottomCenter(gb, edge->source()));

    for(auto it = points.begin(); it != points.end(); it++)
    {
        ogdf::DPoint pt = *it;
        QPointF ptnext(this->scenePoint(gb, edge->target(), pt.m_x, pt.m_y));
        path.lineTo(ptnext);
    }

    this->_scene->addPath(path, QPen(Qt::darkGray, 2));

    auto itarrowstart = points.get(points.size() - 2);
    auto itarrowend = points.get(points.size() - 1);

    this->drawArrow(this->scenePoint(gb, edge->target(), (*itarrowstart).m_x, (*itarrowstart).m_y),
                    this->scenePoint(gb, edge->target(), (*itarrowend).m_x, (*itarrowend).m_y),
                    QColor(Qt::darkYellow)); //QString::fromStdString(ga.strokeColor(edge).toString())));
}

void DisassemblerGraphView::drawArrow(const QPointF &from, const QPointF &to, const QColor& color)
{
    QPolygonF arrowhead;
    QLineF line(to, from);

    double angle = ::acos(line.dx() / line.length());

    if(line.dy() > 0)
        angle = (PI / 2) - angle;

    QPointF p1 = line.p1() + QPointF(::sin(angle + PI / 3) * ARROW_SIZE,
                                     ::cos(angle + PI / 3) * ARROW_SIZE);

    QPointF p2 = line.p1() + QPointF(::sin(angle + PI - PI / 3) * ARROW_SIZE,
                                     ::cos(angle + PI - PI / 3) * ARROW_SIZE);

    arrowhead << line.p1() << p1 << p2;
    this->_scene->addLine(line, QPen(color, 2));
    this->_scene->addPolygon(arrowhead, QPen(color, 2), QBrush(color));
}

QPointF DisassemblerGraphView::topCenter(REDasm::GraphBuilder &gb, REDasm::GraphBuilder::Node *node)
{
    ogdf::GraphAttributes& ga = gb.graphAttributes();
    return this->scenePoint(gb, node, ga.x(node) + ga.width(node) / 2, ga.y(node));
}

QPointF DisassemblerGraphView::bottomCenter(REDasm::GraphBuilder &gb, REDasm::GraphBuilder::Node *node)
{
    ogdf::GraphAttributes& ga = gb.graphAttributes();
    return this->scenePoint(gb, node, ga.x(node) + ga.width(node) / 2, ga.y(node) + ga.height(node));
}

QPointF DisassemblerGraphView::scenePoint(REDasm::GraphBuilder &gb, REDasm::GraphBuilder::Node *node, double x, double y) const
{
    ogdf::GraphAttributes& ga = gb.graphAttributes();
    return QPointF(x - ga.width(node) / 2, y - ga.height(node) / 2);
}

QPointF DisassemblerGraphView::scenePoint(FunctionBlockItem* fbi, double x, double y) const
{
    QRectF fbir = fbi->boundingRect();
    return QPointF(x - fbir.width() / 2, y - fbir.height() / 2);
}

QPointF DisassemblerGraphView::scenePoint(double x, double y) const
{
    QRectF r = this->rect();
    return QPointF(x - r.width() / 2, y - r.height() / 2);
}
*/
