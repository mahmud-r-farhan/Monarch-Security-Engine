import { test } from 'node:test';
import assert from 'node:assert/strict';
import net from 'node:net';
import dgram from 'node:dgram';
import {
  expandTargets,
  parseArpOutput,
  parsePortList,
  inferOsFromDevice,
  checkTcpPort,
  checkUdpPort,
  runNetworkDiscovery,
} from '../src/modules/netdiscovery.js';

test('parsePortList correctly parses ranges and lists', () => {
  assert.deepEqual(parsePortList('80, 443, 8000-8003'), [80, 443, 8000, 8001, 8002, 8003]);
  assert.deepEqual(parsePortList([22, 80]), [22, 80]);
  assert.deepEqual(parsePortList('invalid'), []);
});

test('expandTargets expands single IPs, ranges, and CIDR subnets', () => {
  const res1 = expandTargets('192.168.1.1, 192.168.1.2-192.168.1.4');
  assert.equal(res1.count, 4);
  assert.deepEqual(res1.ips, ['192.168.1.1', '192.168.1.2', '192.168.1.3', '192.168.1.4']);

  const res2 = expandTargets('10.0.0.0/30');
  assert.equal(res2.count, 2);
  assert.deepEqual(res2.ips, ['10.0.0.1', '10.0.0.2']);
});

test('parseArpOutput parses output strings from ARP table', () => {
  const winArp = `
Interface: 192.168.1.10 --- 0x11
  Internet Address      Physical Address      Type
  192.168.1.1           00-11-22-33-44-55     dynamic
  192.168.1.255         ff-ff-ff-ff-ff-ff     static
`;
  const parsedWin = parseArpOutput(winArp);
  assert.equal(parsedWin.length, 1);
  assert.equal(parsedWin[0].ip, '192.168.1.1');
  assert.equal(parsedWin[0].mac, '00:11:22:33:44:55');

  const nixArp = `
? (10.0.0.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]
`;
  const parsedNix = parseArpOutput(nixArp);
  assert.equal(parsedNix.length, 1);
  assert.equal(parsedNix[0].ip, '10.0.0.1');
  assert.equal(parsedNix[0].mac, 'aa:bb:cc:dd:ee:ff');
});

test('inferOsFromDevice accurately categorizes operating systems', () => {
  assert.equal(inferOsFromDevice({ vendor: 'Apple, Inc.', openPorts: [] }), 'Apple macOS/iOS');
  assert.equal(inferOsFromDevice({ vendor: 'Microsoft Corporation', openPorts: [{ port: 445 }] }), 'Windows');
  assert.equal(inferOsFromDevice({ vendor: 'Intel', openPorts: [{ port: 22, banner: 'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1' }] }), 'Linux');
  assert.equal(inferOsFromDevice({ vendor: 'Ubiquiti Inc.', openPorts: [] }), 'Embedded Network Appliance');
  assert.equal(inferOsFromDevice(null), 'Unknown');
});

test('checkTcpPort detects open TCP port and extracts banner', async () => {
  const server = net.createServer((socket) => {
    socket.write('SSH-2.0-OpenSSH_8.2p1\r\n');
  });

  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = server.address().port;

  const res = await checkTcpPort('127.0.0.1', port, 500);
  assert.equal(res.open, true);
  assert.equal(res.port, port);
  assert.match(res.service, /SSH/i);

  server.close();
});

test('checkUdpPort probes UDP socket', async () => {
  const server = dgram.createSocket('udp4');
  server.on('message', (msg, rinfo) => {
    server.send(Buffer.from('PONG'), rinfo.port, rinfo.address);
  });
  await new Promise((resolve) => server.bind(0, '127.0.0.1', resolve));
  const port = server.address().port;

  const res = await checkUdpPort('127.0.0.1', port, 500);
  assert.equal(res.open, true);
  assert.equal(res.port, port);
  assert.equal(res.banner, 'PONG');

  server.close();
});

test('runNetworkDiscovery completes successfully on local subnet', async () => {
  const events = [];
  const result = await runNetworkDiscovery({
    subnet: '127.0.0.1/32',
    mode: 'fast',
    pingTimeout: 200,
    portTimeout: 200,
    onEvent: (ev) => events.push(ev.type),
  });

  assert.ok(result.devices.length >= 1);
  assert.ok(events.includes('status'));
  assert.ok(events.includes('done'));
});
