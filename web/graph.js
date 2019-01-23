
GraphView = {

    graph: null,

    initGraph: function () {
        this.graph = new dagre.graphlib.Graph();
        this.graph.setDefaultEdgeLabel(function() { return { }; });
        this.graph.setGraph({ });
    },

    initPage: function () {
        document.designMode = 'on';
        window.ondrop = function() { return false; };                           // Disable text dragging
        window.onkeydown = function(e) { return e.key.startsWith('Arrow'); };   // Disable character input
    },

    renderGraph: function (width, height, margins) {
        dagre.layout(this.graph, { acyclier: 'greedy' });
        d3.selectAll('svg > :not(defs)').remove();

        var svg = d3.select('svg');
        var g = svg.append('g');
        var zoom = d3.zoom().on('zoom', function() { g.attr('transform', d3.event.transform); });
        g.call(new dagreD3.render(), this.graph);
        var mid = (width - this.graph.graph().width) / 2;
        g.attr('transform', 'translate(' + mid + ',' + margins + ')');
        svg.call(zoom.filter(function() { return d3.event.ctrlKey; }));
        svg.attr('height', height);
        svg.attr('width', width);
    },

    appendCss: function (content) {
        var css = document.createElement('style');
        css.type = 'text/css';
        document.head.appendChild(css);
        css.innerText = content;
    },

    zoomOn: function (line) {
        var n = d3.select('div[data-lineroot][data-line="' + line + '"]').node();
        console.log('div[data-lineroot][data-line="' + line + '"]');

        while(n && !n.classList.contains('label'))
            n = n.parentElement;

        if(n) {
            var zoomscale = 2.0;
            var bb = n.getBBox();
            var s = d3.select(n);
        }
    },

    setNode: function (nodeId, title, content) {
        this.graph.setNode(nodeId, {
            labelType: 'html',
            label: title + content
        });
    },

    setEdge: function (nodeId, edgeId, color) {
        this.graph.setEdge(nodeId, edgeId, {
            style: 'stroke: ' + color + '; fill: transparent',
            arrowheadStyle: 'stroke: ' + color + '; fill: ' + color
        });
    }

};
