import { WebSocketServer, WebSocket } from 'ws';

export class MonarchWsServer {
  constructor() {
    this.wss = null;
    this.clients = new Set();
  }

  attach(httpServer) {
    this.wss = new WebSocketServer({ server: httpServer, path: '/ws' });

    this.wss.on('connection', (ws, req) => {
      ws.subscriptions = new Set(['all']);
      ws.isAlive = true;
      this.clients.add(ws);

      ws.on('pong', () => {
        ws.isAlive = true;
      });

      ws.on('message', (data) => {
        try {
          const msg = JSON.parse(data.toString());
          if (msg.action === 'ping') {
            ws.send(JSON.stringify({ action: 'pong', timestamp: Date.now() }));
          } else if (msg.action === 'subscribe' && msg.channel) {
            ws.subscriptions.add(msg.channel);
            ws.send(JSON.stringify({ action: 'subscribed', channel: msg.channel }));
          } else if (msg.action === 'unsubscribe' && msg.channel) {
            ws.subscriptions.delete(msg.channel);
          }
        } catch {
          // ignore malformed message
        }
      });

      ws.on('close', () => {
        this.clients.delete(ws);
      });

      ws.on('error', () => {
        this.clients.delete(ws);
      });

      // Send welcome
      ws.send(JSON.stringify({
        type: 'welcome',
        message: 'Connected to Monarch Security Engine Real-time WebSocket',
        timestamp: Date.now(),
      }));
    });

    // Heartbeat ping interval
    const interval = setInterval(() => {
      for (const ws of this.clients) {
        if (!ws.isAlive) {
          this.clients.delete(ws);
          ws.terminate();
          continue;
        }
        ws.isAlive = false;
        ws.ping();
      }
    }, 30000);

    this.wss.on('close', () => {
      clearInterval(interval);
    });

    console.log('      WebSocket server attached at /ws');
  }

  broadcast(channel, payload) {
    if (!this.wss) return;
    const msg = JSON.stringify({ channel, data: payload, timestamp: Date.now() });
    for (const ws of this.clients) {
      if (ws.readyState === WebSocket.OPEN) {
        if (ws.subscriptions.has('all') || ws.subscriptions.has(channel)) {
          ws.send(msg);
        }
      }
    }
  }

  getClientCount() {
    return this.clients.size;
  }
}

export const wsServer = new MonarchWsServer();
