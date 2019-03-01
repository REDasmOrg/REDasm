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
            if(e.button === 0) // Left button
                channelobjects.graphchannel.followUnderCursor();
        });

        document.addEventListener('click', function(e) {
            let line = document.querySelector('.seek');
            if(line)
                line.classList.remove('seek');

            line = e.target;

            while(line && !('lineroot' in line.dataset))
                line = line.parentElement;

            if(line)
                line.classList.add('seek');
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

    isNodeInViewport: function (node) {
        let r = el.getBoundingClientRect();
        let wh = (window.innerHeight || document.documentElement.clientHeight);
        let ww = (window.innerWidth || document.documentElement.clientWidth);
        return ((r.left >= 0) && (r.top >= 0) && ((r.left + r.width) <= ww) && ((r.top + r.height) <= wh));
    },

    isNodePartiallyInViewport: function (node) {
        let r = node.getBoundingClientRect();
        let wh = (window.innerHeight || document.documentElement.clientHeight);
        let ww = (window.innerWidth || document.documentElement.clientWidth);
        let vertinview = (r.top <= wh) && ((r.top + r.height) >= 0);
        let horinview = (r.left <= ww) && ((r.left + r.width) >= 0);
        return vertinview && horinview;
    },

    focusOnLine: function(line) {
        let n = this.nodeFromLine(line)

        if(!n)
            return;

        if(!this.isNodePartiallyInViewport(n.firstElementChild)) // node ->  rect
            this.focusOnNode(n);
    },

    focusOnNode: function(node) {
        let scale = d3.zoomTransform(this.svg.node()).k;
        let container = document.getElementById('container');
        let cx = this.getNodeCenterX(node, container.clientWidth, scale);
        this.svg.call(this.zoom.transform, d3.zoomIdentity.translate(cx, this.graphMargins).scale(scale));
    },

    nodeFromLine: function(line) {
        let n = document.querySelector("div[data-line='" + line + "']");

        while(n) {
            if((n.tagName === 'g') && n.classList.contains("node"))
                break;

            n = n.parentElement;
        }

        return n;
    },

    getNodeCenterX: function (node, viewerWidth, scale) {
        let bb = node.getBBox();
        let matrix = this.getTransformMatrix(node);
        let tx = (matrix.e * scale);
        let x = ((viewerWidth - bb.width) / 2) - bb.x - tx;
        return x;
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
        console.log('div[data-lineroot][data-line="' + line + '"]');

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
