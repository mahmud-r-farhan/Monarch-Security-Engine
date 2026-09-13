/**
 * IEEE OUI (Organizationally Unique Identifier) Hardware Vendor Resolver.
 * Resolves MAC address prefixes (first 3 or 4 octets) to hardware manufacturers.
 */

const OUI_MAP = {
  // Apple
  '00:03:93': 'Apple',
  '00:05:02': 'Apple',
  '00:0a:27': 'Apple',
  '00:0a:95': 'Apple',
  '00:10:fa': 'Apple',
  '00:14:51': 'Apple',
  '00:16:cb': 'Apple',
  '00:17:f2': 'Apple',
  '00:19:e3': 'Apple',
  '00:1b:63': 'Apple',
  '00:1c:b3': 'Apple',
  '00:1d:4f': 'Apple',
  '00:1e:52': 'Apple',
  '00:1e:c2': 'Apple',
  '00:1f:5b': 'Apple',
  '00:1f:f3': 'Apple',
  '00:21:e9': 'Apple',
  '00:22:41': 'Apple',
  '00:23:12': 'Apple',
  '00:23:32': 'Apple',
  '00:23:6c': 'Apple',
  '00:24:36': 'Apple',
  '00:25:00': 'Apple',
  '00:25:4b': 'Apple',
  '00:26:08': 'Apple',
  '00:26:4a': 'Apple',
  '00:26:b0': 'Apple',
  '00:26:bb': 'Apple',
  '3c:22:fb': 'Apple',
  '40:6c:8f': 'Apple',
  '48:60:5f': 'Apple',
  '50:bc:96': 'Apple',
  '60:f8:1d': 'Apple',
  '70:3e:ac': 'Apple',
  '78:4f:43': 'Apple',
  '88:66:5a': 'Apple',
  '90:27:e4': 'Apple',
  'a4:83:e7': 'Apple',
  'ac:bc:32': 'Apple',
  'b8:78:2e': 'Apple',
  'bc:52:b7': 'Apple',
  'c8:69:cd': 'Apple',
  'dc:a9:04': 'Apple',
  'f0:18:98': 'Apple',

  // Raspberry Pi Foundation
  'b8:27:eb': 'Raspberry Pi Foundation',
  'dc:a6:32': 'Raspberry Pi Foundation',
  'e4:5f:01': 'Raspberry Pi Foundation',
  '28:cd:c1': 'Raspberry Pi Trading',

  // Espressif (ESP8266, ESP32 IoT devices)
  '18:fe:34': 'Espressif Inc.',
  '24:0a:c4': 'Espressif Inc.',
  '24:6f:28': 'Espressif Inc.',
  '24:b2:de': 'Espressif Inc.',
  '30:ae:a4': 'Espressif Inc.',
  '3c:61:05': 'Espressif Inc.',
  '3c:71:bf': 'Espressif Inc.',
  '84:0d:8e': 'Espressif Inc.',
  '84:f3:eb': 'Espressif Inc.',
  'a4:cf:12': 'Espressif Inc.',
  'bc:dd:c2': 'Espressif Inc.',
  'cc:50:e3': 'Espressif Inc.',

  // Cisco
  '00:00:0c': 'Cisco Systems',
  '00:01:42': 'Cisco Systems',
  '00:01:43': 'Cisco Systems',
  '00:01:63': 'Cisco Systems',
  '00:01:64': 'Cisco Systems',
  '00:01:96': 'Cisco Systems',
  '00:01:97': 'Cisco Systems',
  '00:02:16': 'Cisco Systems',
  '00:02:17': 'Cisco Systems',
  '00:02:4a': 'Cisco Systems',
  '00:02:4b': 'Cisco Systems',
  '00:02:7d': 'Cisco Systems',
  '00:02:7e': 'Cisco Systems',
  '00:02:fc': 'Cisco Systems',
  '00:02:fd': 'Cisco Systems',
  '00:03:31': 'Cisco Systems',
  '00:03:32': 'Cisco Systems',
  '00:03:6b': 'Cisco Systems',
  '00:03:6c': 'Cisco Systems',
  '00:03:9f': 'Cisco Systems',
  '00:03:a0': 'Cisco Systems',
  '00:03:e3': 'Cisco Systems',

  // Intel
  '00:02:b3': 'Intel Corporate',
  '00:03:47': 'Intel Corporate',
  '00:04:23': 'Intel Corporate',
  '00:07:e9': 'Intel Corporate',
  '00:0e:0c': 'Intel Corporate',
  '00:0e:35': 'Intel Corporate',
  '00:11:11': 'Intel Corporate',
  '00:12:f0': 'Intel Corporate',
  '00:13:02': 'Intel Corporate',
  '00:13:20': 'Intel Corporate',
  '00:13:e8': 'Intel Corporate',
  '00:15:00': 'Intel Corporate',
  '00:16:6f': 'Intel Corporate',
  '00:16:76': 'Intel Corporate',
  '00:16:ea': 'Intel Corporate',
  '00:16:eb': 'Intel Corporate',
  '00:18:de': 'Intel Corporate',
  '00:19:d1': 'Intel Corporate',
  '00:1b:21': 'Intel Corporate',
  '00:1b:77': 'Intel Corporate',
  '00:1c:bf': 'Intel Corporate',
  '00:1c:c0': 'Intel Corporate',
  '00:1d:e0': 'Intel Corporate',
  '00:1e:64': 'Intel Corporate',
  '00:1e:65': 'Intel Corporate',

  // TP-Link
  '00:1d:0f': 'TP-Link Technologies',
  '00:21:27': 'TP-Link Technologies',
  '00:23:cd': 'TP-Link Technologies',
  '00:25:86': 'TP-Link Technologies',
  '14:cc:20': 'TP-Link Technologies',
  '18:a6:f7': 'TP-Link Technologies',
  '30:de:4b': 'TP-Link Technologies',
  '50:c7:bf': 'TP-Link Technologies',
  '60:32:b1': 'TP-Link Technologies',
  '70:4f:57': 'TP-Link Technologies',
  '98:48:27': 'TP-Link Technologies',
  'ac:84:c6': 'TP-Link Technologies',
  'c0:06:c3': 'TP-Link Technologies',
  'ec:08:6b': 'TP-Link Technologies',

  // Netgear
  '00:09:5b': 'Netgear',
  '00:0f:b5': 'Netgear',
  '00:14:6c': 'Netgear',
  '00:18:4d': 'Netgear',
  '00:1b:2f': 'Netgear',
  '00:1e:2a': 'Netgear',
  '00:1f:33': 'Netgear',
  '00:22:3f': 'Netgear',
  '00:24:b2': 'Netgear',
  '00:26:f2': 'Netgear',
  '20:e5:2a': 'Netgear',
  '84:1b:5e': 'Netgear',
  '9c:3d:cf': 'Netgear',

  // ASUS
  '00:0c:6e': 'ASUSTek Computer',
  '00:11:2f': 'ASUSTek Computer',
  '00:11:d8': 'ASUSTek Computer',
  '00:13:d4': 'ASUSTek Computer',
  '00:15:af': 'ASUSTek Computer',
  '00:17:31': 'ASUSTek Computer',
  '00:18:f3': 'ASUSTek Computer',
  '00:1a:92': 'ASUSTek Computer',
  '00:1b:fc': 'ASUSTek Computer',
  '00:1d:60': 'ASUSTek Computer',
  '00:1e:8c': 'ASUSTek Computer',
  '04:d9:f5': 'ASUSTek Computer',
  '08:62:66': 'ASUSTek Computer',
  '10:bf:48': 'ASUSTek Computer',
  '2c:4d:54': 'ASUSTek Computer',
  '38:2c:4a': 'ASUSTek Computer',
  '40:16:7e': 'ASUSTek Computer',

  // Ubiquiti Networks
  '00:15:6d': 'Ubiquiti Networks',
  '00:27:22': 'Ubiquiti Networks',
  '04:18:d6': 'Ubiquiti Networks',
  '24:a4:3c': 'Ubiquiti Networks',
  '44:d9:e7': 'Ubiquiti Networks',
  '68:72:51': 'Ubiquiti Networks',
  '74:83:c2': 'Ubiquiti Networks',
  '78:8a:20': 'Ubiquiti Networks',
  '80:2a:a8': 'Ubiquiti Networks',
  'b4:fb:e4': 'Ubiquiti Networks',
  'dc:9f:db': 'Ubiquiti Networks',
  'e0:63:da': 'Ubiquiti Networks',
  'f0:9f:c2': 'Ubiquiti Networks',

  // Synology
  '00:11:32': 'Synology Incorporated',

  // QNAP
  '00:08:9b': 'QNAP Systems',
  '24:5e:be': 'QNAP Systems',

  // Dell
  '00:06:5b': 'Dell Inc.',
  '00:08:74': 'Dell Inc.',
  '00:0b:db': 'Dell Inc.',
  '00:0d:56': 'Dell Inc.',
  '00:0f:1f': 'Dell Inc.',
  '00:11:43': 'Dell Inc.',
  '00:12:3f': 'Dell Inc.',
  '00:13:72': 'Dell Inc.',
  '00:14:22': 'Dell Inc.',
  '18:03:73': 'Dell Inc.',
  '18:66:da': 'Dell Inc.',
  '24:b6:fd': 'Dell Inc.',
  '34:17:eb': 'Dell Inc.',

  // HP / Hewlett Packard Enterprise
  '00:01:e6': 'Hewlett Packard',
  '00:01:e7': 'Hewlett Packard',
  '00:02:a5': 'Hewlett Packard',
  '00:04:ea': 'Hewlett Packard',
  '00:08:02': 'Hewlett Packard',
  '00:0b:cd': 'Hewlett Packard',
  '00:0e:7f': 'Hewlett Packard',
  '00:11:0a': 'Hewlett Packard',
  '00:12:79': 'Hewlett Packard',
  '00:13:21': 'Hewlett Packard',
  '00:14:38': 'Hewlett Packard',
  '3c:d9:2b': 'Hewlett Packard',

  // Samsung
  '00:00:f0': 'Samsung Electronics',
  '00:02:78': 'Samsung Electronics',
  '00:07:ab': 'Samsung Electronics',
  '00:09:18': 'Samsung Electronics',
  '00:0d:ae': 'Samsung Electronics',
  '00:12:47': 'Samsung Electronics',
  '00:12:fb': 'Samsung Electronics',
  '00:15:99': 'Samsung Electronics',
  '00:16:32': 'Samsung Electronics',
  '00:16:6b': 'Samsung Electronics',
  '00:16:6c': 'Samsung Electronics',
  '00:17:c9': 'Samsung Electronics',
  '00:17:d5': 'Samsung Electronics',
  '00:18:af': 'Samsung Electronics',
  '08:08:c2': 'Samsung Electronics',
  '14:bb:6e': 'Samsung Electronics',
  '50:85:69': 'Samsung Electronics',
  '84:25:db': 'Samsung Electronics',
  'ac:5f:3e': 'Samsung Electronics',

  // Google
  '00:1a:11': 'Google, Inc.',
  '3c:5a:37': 'Google, Inc.',
  '54:60:09': 'Google, Inc.',
  '70:3a:cb': 'Google, Inc.',
  '94:eb:cd': 'Google, Inc.',
  'a4:77:33': 'Google, Inc.',
  'd8:6c:63': 'Google, Inc.',
  'f4:03:04': 'Google, Inc.',
  'f4:f5:e8': 'Google, Inc.',

  // Amazon
  '00:fc:8b': 'Amazon Technologies',
  '38:f7:3d': 'Amazon Technologies',
  '40:b4:cd': 'Amazon Technologies',
  '44:65:0d': 'Amazon Technologies',
  '50:dc:e7': 'Amazon Technologies',
  '68:37:e9': 'Amazon Technologies',
  '74:75:48': 'Amazon Technologies',
  '84:d6:d0': 'Amazon Technologies',
  'ac:63:be': 'Amazon Technologies',
  'cc:9e:a2': 'Amazon Technologies',
  'fc:65:de': 'Amazon Technologies',

  // Microsoft
  '00:03:ff': 'Microsoft Corporation',
  '00:0d:3a': 'Microsoft Corporation',
  '00:12:5a': 'Microsoft Corporation',
  '00:15:5d': 'Microsoft (Hyper-V)',
  '00:17:fa': 'Microsoft Corporation',
  '00:1d:d8': 'Microsoft Corporation',
  '00:22:48': 'Microsoft Corporation',
  '00:25:ae': 'Microsoft Corporation',
  '28:18:78': 'Microsoft Corporation',
  '7c:1e:52': 'Microsoft Corporation',

  // Huawei
  '00:18:82': 'Huawei Technologies',
  '00:19:e0': 'Huawei Technologies',
  '00:1e:10': 'Huawei Technologies',
  '00:25:9e': 'Huawei Technologies',
  '00:e0:fc': 'Huawei Technologies',
  '04:25:c5': 'Huawei Technologies',
  '20:0b:c7': 'Huawei Technologies',
  '48:46:fb': 'Huawei Technologies',

  // Xiaomi
  '00:ec:0a': 'Xiaomi Communications',
  '14:f6:5a': 'Xiaomi Communications',
  '28:6c:07': 'Xiaomi Communications',
  '34:80:dc': 'Xiaomi Communications',
  '58:44:98': 'Xiaomi Communications',
  '64:09:80': 'Xiaomi Communications',
  '7c:49:eb': 'Xiaomi Communications',
  'ac:c1:ee': 'Xiaomi Communications',

  // Sony
  '00:01:4a': 'Sony Corporation',
  '00:04:1f': 'Sony Corporation',
  '00:0a:d9': 'Sony Corporation',
  '00:13:15': 'Sony Corporation',
  '00:15:c1': 'Sony Corporation',
  '00:19:c1': 'Sony Corporation',
  '00:1d:ba': 'Sony Corporation',
  '00:24:8d': 'Sony Corporation',
  '70:9e:29': 'Sony Interactive Entertainment',
  'f8:46:1c': 'Sony Interactive Entertainment',

  // VMware / Virtualization
  '00:05:69': 'VMware, Inc.',
  '00:0c:29': 'VMware, Inc.',
  '00:50:56': 'VMware, Inc.',
  '08:00:27': 'Oracle VirtualBox',
  '52:54:00': 'QEMU / KVM',

  // Realtek
  '00:07:0e': 'Realtek Semiconductor',
  '00:0e:2e': 'Realtek Semiconductor',
  '00:18:e7': 'Realtek Semiconductor',
  '52:54:4c': 'Realtek Semiconductor',

  // Broadcom
  '00:0a:f7': 'Broadcom Corporation',
  '00:10:18': 'Broadcom Corporation',
  '00:1a:2a': 'Broadcom Corporation',
  '00:1b:e9': 'Broadcom Corporation',

  // D-Link
  '00:05:5d': 'D-Link System',
  '00:0d:88': 'D-Link System',
  '00:0f:3d': 'D-Link System',
  '00:11:95': 'D-Link System',
  '00:13:46': 'D-Link System',
  '00:15:e9': 'D-Link System',
  '00:17:9a': 'D-Link System',
  '00:18:e7': 'D-Link System',
  '14:d6:4d': 'D-Link System',
  '28:10:7b': 'D-Link System',
};

/**
 * Normalizes a MAC string to standard xx:xx:xx:xx:xx:xx format.
 */
export function normalizeMac(raw) {
  if (!raw) return '';
  const cleaned = raw.trim().toLowerCase().replace(/[-.]/g, ':');
  // Check format
  const parts = cleaned.split(':');
  if (parts.length === 6) {
    return parts.map(p => p.padStart(2, '0')).join(':');
  }
  return cleaned;
}

/**
 * Resolves a MAC address to a known vendor string, or 'Unknown / Generic'.
 */
export function resolveVendor(mac) {
  const norm = normalizeMac(mac);
  if (!norm) return 'Unknown';
  // Check 3-octet prefix (e.g. "00:11:22")
  const prefix3 = norm.slice(0, 8);
  if (OUI_MAP[prefix3]) return OUI_MAP[prefix3];

  // Multicast / Broadcast / Local bit checks
  const firstByte = parseInt(norm.slice(0, 2), 16);
  if (!isNaN(firstByte)) {
    if (firstByte & 0x01) return 'Multicast / Broadcast Group';
    if (firstByte & 0x02) return 'Locally Administered (Randomized MAC)';
  }

  return 'Unknown Manufacturer';
}
