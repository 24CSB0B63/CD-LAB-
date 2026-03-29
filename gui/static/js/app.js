document.addEventListener('DOMContentLoaded', () => {
    // Initialize CodeMirror
    const editorEl = document.getElementById('code-editor');
    const editor = CodeMirror.fromTextArea(editorEl, {
        lineNumbers: true,
        mode: 'text/x-c++src',
        theme: 'dracula',
        indentUnit: 4,
        matchBrackets: true
    });

    const analyzeBtn = document.getElementById('analyze-btn');
    const statusBadge = document.getElementById('status-badge');
    const loadingOverlay = document.getElementById('loading');
    const cyContainer = document.getElementById('cy');
    const placeholder = document.getElementById('placeholder');
    
    let cyObj = null;

    analyzeBtn.addEventListener('click', async () => {
        const code = editor.getValue();
        if (!code.trim()) {
            alert("Please enter some C++ code.");
            return;
        }

        // Show loading state
        analyzeBtn.disabled = true;
        loadingOverlay.style.display = 'flex';
        statusBadge.textContent = "Analyzing...";
        statusBadge.className = "badge";
        placeholder.style.display = 'none';

        if (cyObj) {
            cyObj.destroy();
            cyObj = null;
        }

        try {
            const response = await fetch('/analyze', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ code })
            });

            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.error || "Analysis failed");
            }

            renderCFG(data.cfg, data.is_vulnerable);
            // We don't set statusBadge.textContent here anymore because renderCFG handles it
            
        } catch (error) {
            console.error("Error analyzing code:", error);
            statusBadge.textContent = "Error";
            statusBadge.className = "badge error";
            placeholder.style.display = 'block';
            placeholder.textContent = "Error: " + error.message;
            placeholder.style.color = "var(--danger)";
        } finally {
            analyzeBtn.disabled = false;
            loadingOverlay.style.display = 'none';
        }
    });

    function renderCFG(cfgData, isVulnerable) {
        const elements = [];
        let hasTaint = false;
        let lineMapping = {};

        // Flatten JSON into cytoscape nodes and edges
        Object.entries(cfgData).forEach(([funcName, funcData]) => {
            funcData.BasicBlocks.forEach(bb => {
                const nodeId = `${funcName}_${bb.Name}`;
                
                // Build HTML-like label for the basic block containing instructions
                let anyTainted = false;
                let instructionsText = bb.Instructions.map(inst => {
                    const isTaint = inst.tainted === true || inst.tainted === "true";
                    const lineStr = (inst.line && inst.line > 0) ? `[Line ${inst.line}] ` : "";
                    
                    if (inst.line && inst.line > 0) {
                        if (!lineMapping[nodeId]) lineMapping[nodeId] = [];
                        lineMapping[nodeId].push(inst.line);
                    }

                    if (isTaint) {
                        anyTainted = true;
                        hasTaint = true;
                        return `[TAINTED] ${lineStr}${inst.text}`;
                    }
                    return `${lineStr}${inst.text}`;
                }).join('\n');

                elements.push({
                    data: {
                        id: nodeId,
                        label: `${funcName}() - ${bb.Name}\n\n${instructionsText}`,
                        isTainted: anyTainted
                    }
                });

                // Add edges
                bb.Successors.forEach(succ => {
                    const targetId = `${funcName}_${succ}`;
                    elements.push({
                        data: {
                            id: `${nodeId}->${targetId}`,
                            source: nodeId,
                            target: targetId
                        }
                    });
                });
            });
        });

        if (isVulnerable) {
            statusBadge.textContent = "Code is VULNERABLE!";
            statusBadge.style.color = "#000";
            statusBadge.style.backgroundColor = "var(--danger)";
        } else {
            statusBadge.textContent = "Code is SAFE";
            statusBadge.style.color = "#000";
            statusBadge.style.backgroundColor = "var(--success)";
        }

        // Initialize Cytoscape
        cyObj = cytoscape({
            container: cyContainer,
            elements: elements,
            style: [
                {
                    selector: 'node',
                    style: {
                        'background-color': '#161b22',
                        'border-width': 2,
                        'border-color': '#30363d',
                        'shape': 'round-rectangle',
                        'width': 'label',
                        'height': 'label',
                        'padding': 20,
                        'label': 'data(label)',
                        'text-valign': 'center',
                        'text-halign': 'center',
                        'text-wrap': 'wrap',
                        'font-family': 'monospace',
                        'font-size': 14,
                        'color': '#c9d1d9',
                        'text-justification': 'left'
                    }
                },
                {
                    selector: 'node[?isTainted]',
                    style: {
                        'border-color': '#f85149',
                        'border-width': 4,
                        'box-shadow': '0 0 15px rgba(248, 81, 73, 0.6)',
                        'color': '#ff7b72'
                    }
                },
                {
                    selector: 'edge',
                    style: {
                        'width': 6,
                        'line-color': '#58a6ff',
                        'target-arrow-color': '#58a6ff',
                        'target-arrow-shape': 'triangle',
                        'curve-style': 'bezier',
                        'arrow-scale': 3
                    }
                }
            ],
            layout: {
                name: 'breadthfirst',
                directed: true,
                spacingFactor: 1.0,
                padding: 30
            }
        });

        // Add node click listener to highlight code
        cyObj.on('tap', 'node', function(evt) {
            const node = evt.target;
            const nid = node.id();
            if (lineMapping[nid] && lineMapping[nid].length > 0) {
                // Highlight the first line associated with this block
                const line = lineMapping[nid][0];
                editor.setCursor({line: line - 1, ch: 0});
                editor.setSelection({line: line - 1, ch: 0}, {line: line, ch: 0});
                editor.focus();
                
                // Optional: flash status to show it worked
                statusBadge.textContent = `Jumped to Line ${line}`;
                setTimeout(() => {
                    statusBadge.textContent = hasTaint ? "Vulnerabilities Found!" : "Success";
                }, 2000);
            } else {
                statusBadge.textContent = "No source line info for this block";
                setTimeout(() => {
                    statusBadge.textContent = hasTaint ? "Vulnerabilities Found!" : "Success";
                }, 2000);
            }
        });

        // Add a slight zoom out to fit nicely
        cyObj.fit();
    }
});
