var GraphView = {
    domParser: null,
    graph: null,
    svg: null,
    g: null,
    zoom: null,
    graphMargins: 20,

    initPage: function () {
        window.graphView = this;
        document.designMode = 'on';
        window.ondrop = function() { return false; };                           // Disable text dragging
        window.onkeydown = function(e) { return e.key.startsWith('Arrow'); };   // Disable character input
        this.domParser = new DOMParser();

        window.addEventListener("resize", function() {
            graphView.renderGraph();
        });

        document.addEventListener('keydown', function(e) {
            if(e.code === 'Space')
                channelobjects.graphchannel.switchToListing();
            else if(e.key === 'x')
                channelobjects.graphchannel.showReferencesUnderCursor();
        });

        document.addEventListener('dblclick', function(e) {
            if(e.button === 0) { // Left button
                channelobjects.graphchannel.followUnderCursor();
                graphView.unselectAll();
            }
        });

        document.addEventListener('click', function(e) {
            if(!('line' in e.target.dataset))
                return;

            channelobjects.graphchannel.moveTo(e.target.dataset.line, e.target.innerText);
        });

        document.addEventListener('click', function(e) {
            let oldhighlight = document.querySelectorAll('.highlight'); // Remove old highlighting (1)
            oldhighlight.forEach(function(e) { e.classList.remove('highlight'); }); // Remove old highlighting (2)
            if(e.target.tagName !== 'SPAN')
                return;

            let word = e.target.innerText;
            let query = '//span[text()=\"' + word + '\"]';
            let xhl = document.evaluate(query, document, null, XPathResult.ORDERED_NODE_SNAPSHOT_TYPE); // Find all spans
            for(var i = 0; i < xhl.snapshotLength; i++)
                xhl.snapshotItem(i).classList.add('highlight');     // Apply highlighting
        });
    },

    initGraph: function () {
        this.graph = new dagre.graphlib.Graph();
        this.graph.setDefaultEdgeLabel(function() { return { }; });
        this.graph.setGraph({ ranker: "longest-path",
                              nodesep: 100,
                              ranksep: 75 });
    },

    renderGraph: function () {
        if (this.g)
            this.g.remove();

        let container = document.getElementById('container');

        this.svg = d3.select('svg');
        this.g = this.svg.append('g');

        this.zoom = d3.zoom().filter(this.zoomFilter)
            .on('zoom', this.zoomHandler.bind(this));

        this.svg.call(this.zoom).on('wheel', this.wheelHandler.bind(this))
            .on('dblclick.zoom', null);

        let renderer = new dagreD3.render();
        this.g.call(renderer, this.graph);

        this.svg.selectAll('g.node').on('mousedown', this.nodeMouseDown);
        this.svg.attr('width', container.clientWidth);
        this.svg.attr('height', container.clientHeight);

        let mainnode = this.svg.select('g.node').node();
        this.focusOnNode(mainnode);
    },

    isElementInViewport: function (e) {
        let r = e.getBoundingClientRect();
        let wh = (window.innerHeight || document.documentElement.clientHeight);
        let ww = (window.innerWidth || document.documentElement.clientWidth);
        return ((r.left >= 0) && (r.top >= 0) && ((r.left + r.width) <= ww) && ((r.top + r.height) <= wh));
    },

    isElementPartiallyInViewport: function (e) {
        let r = e.getBoundingClientRect();
        let wh = (window.innerHeight || document.documentElement.clientHeight);
        let ww = (window.innerWidth || document.documentElement.clientWidth);
        let vertinview = (r.top <= wh) && ((r.top + r.height) >= 0);
        let horinview = (r.left <= ww) && ((r.left + r.width) >= 0);
        return vertinview && horinview;
    },

    unselectAll: function() {
        if(window.getSelection)
            window.getSelection().removeAllRanges();
        else if(document.selection)
            document.selection.empty();
    },

    highlightSeek: function(line) {
        let lineobj = document.querySelector('.seek');

        if(lineobj)
            lineobj.classList.remove('seek');

        lineobj = this.lineElement(line);

        while(lineobj && !('lineroot' in lineobj.dataset))
            lineobj = lineobj.parentElement;

        if(lineobj)
            lineobj.classList.add('seek');
    },

    focusOnLine: function(line) {
        this.highlightSeek(line);
        //let n = this.nodeFromLine(line)

        //if(!n)
        //    return;

        //var r = n.firstElementChild; // node ->  rect

        //if(!this.isElementPartiallyInViewport(r))
        //    r.scrollIntoView();
    },

    focusOnNode: function(node) {
        let scale = d3.zoomTransform(this.svg.node()).k;
        let cx = this.getNodeCenterX(node, scale);
        this.svg.call(this.zoom.transform, d3.zoomIdentity.translate(cx, this.graphMargins).scale(scale));
    },

    lineElement: function(line) {
        return document.querySelector("div[data-line='" + line + "']");
    },

    nodeFromLine: function(line) {
        let n = this.lineElement(line);

        while(n) {
            if((n.tagName === 'g') && n.classList.contains("node"))
                break;

            n = n.parentElement;
        }

        return n;
    },

    getNodeCenterX: function (node, scale) {
        let container = document.getElementById('container');
        let bb = node.getBBox();
        let matrix = this.getTransformMatrix(node);
        let tx = (matrix.e * scale);
        let x = ((container.clientWidth - bb.width) / 2) - bb.x - tx;
        return x;
    },

    getNodeCenterY: function (node, scale) {
        let container = document.getElementById('container');
        let bb = node.getBBox();
        let matrix = this.getTransformMatrix(node);
        let ty = (matrix.e * scale);
        let y = ((container.clientHeight - bb.height) / 2) - bb.y - ty;
        return y;
    },

    htmlDecode: function (content) {
        let doc = this.domParser.parseFromString(content, 'text/html');
        return doc.documentElement.textContent;
    },

    getTransformMatrix: function (el) {
        let t = el.transform.baseVal.consolidate();
        return t.matrix;
    },

    zoomFilter: function () {
        if (d3.event.button)
            return false;

        if (d3.event.type === 'wheel')
            return d3.event.ctrlKey;

        return true;
    },

    zoomHandler: function () {
        this.g.attr('transform', d3.event.transform);
    },

    wheelHandler: function () {
        this.zoom.translateBy(this.svg, d3.event.wheelDeltaX, d3.event.wheelDeltaY);
    },

    nodeMouseDown: function () {
        d3.event.stopPropagation();
    },

    zoomOn: function (line) {
        let n = d3.select('div[data-lineroot][data-line="' + line + '"]').node();

        while(n && !n.classList.contains('label'))
            n = n.parentElement;

        if(n) {
            let zoomscale = 2.0;
            let bb = n.getBBox();
            let s = d3.select(n);
        }
    },

    appendCss: function (content) {
        let css = document.createElement('style');
        css.type = 'text/css';
        css.innerText = content;
        document.head.appendChild(css);
    },

    setNode: function (nodeId, title, content) {
        title = this.htmlDecode(title);
        content = this.htmlDecode(content);
        title = '<div contenteditable="false" class="nodetitle">' + title + '</div>';

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
