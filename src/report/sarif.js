/**
 * SARIF (Static Analysis Results Interchange Format) exporter
 * For integration with GitHub Code Scanning, VS Code, etc.
 */

export function renderSarif(scan) {
  const rules = [];
  const results = [];
  const ruleIndex = new Map();

  for (const finding of scan.findings) {
    if (!ruleIndex.has(finding.id)) {
      ruleIndex.set(finding.id, rules.length);
      rules.push({
        id: finding.id,
        name: finding.title,
        shortDescription: { text: finding.title },
        fullDescription: { text: finding.description },
        help: {
          text: finding.remediation || finding.description,
          markdown: finding.remediation ? `**Remediation:**\n\`\`\`\n${finding.remediation}\n\`\`\`` : finding.description,
        },
        properties: {
          tags: [finding.category, finding.severity, 'security', ...(finding.cwe ? [finding.cwe] : []), ...(finding.owasp ? [finding.owasp] : [])],
          severity: finding.severity,
          category: finding.category,
        },
      });
    }

    results.push({
      ruleId: finding.id,
      ruleIndex: ruleIndex.get(finding.id),
      level: sarifLevel(finding.severity),
      message: { text: `${finding.title}: ${finding.description}` },
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri: finding.location || scan.target },
          },
        },
      ],
      properties: {
        severity: finding.severity,
        evidence: finding.evidence,
      },
    });
  }

  return {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'Monarch Security Engine',
            version: scan.version || 'active',
            informationUri: 'https://github.com/mahmud-r-farhan/Monarch-Security-Engine',
            rules,
          },
        },
        invocations: [
          {
            executionSuccessful: true,
            endTimeUtc: scan.finishedAt,
            properties: {
              target: scan.target,
              score: scan.score,
              durationMs: scan.durationMs,
            },
          },
        ],
        results,
      },
    ],
  };
}

function sarifLevel(sev) {
  switch (sev) {
    case 'critical':
    case 'high':
      return 'error';
    case 'medium':
      return 'warning';
    case 'low':
      return 'note';
    case 'info':
    default:
      return 'none';
  }
}
