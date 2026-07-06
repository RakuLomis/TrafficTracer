function startLogStream(wsUrl, panelId) {
    const panel = document.getElementById(panelId);
    if (!panel) return;
    panel.innerHTML = '';
    const ws = new WebSocket(wsUrl);
    ws.onmessage = (e) => {
        const data = JSON.parse(e.data);
        const line = document.createElement('div');
        let cls = 'log-info';
        if (data.line.includes('[WARNING') || data.line.includes('[WARN')) cls = 'log-warn';
        if (data.line.includes('[ERROR')) cls = 'log-error';
        line.className = cls;
        line.textContent = data.line;
        panel.appendChild(line);
        panel.scrollTop = panel.scrollHeight;
    };
    ws.onclose = () => {
        const line = document.createElement('div');
        line.className = 'log-info';
        line.textContent = '--- Log stream ended ---';
        panel.appendChild(line);
    };
    ws.onerror = () => {
        const line = document.createElement('div');
        line.className = 'log-error';
        line.textContent = '--- Log stream error ---';
        panel.appendChild(line);
    };
}
