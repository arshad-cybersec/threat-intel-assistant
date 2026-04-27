import anthropic
from app.config import settings

client = anthropic.Anthropic(api_key=settings.ANTHROPIC_API_KEY)

SYSTEM_PROMPT = """You are an expert cybersecurity threat intelligence analyst with deep knowledge of:
- Threat actor TTPs (Tactics, Techniques, and Procedures)
- MITRE ATT&CK framework
- Malware analysis and reverse engineering
- Vulnerability assessment and CVE analysis
- Indicators of Compromise (IOCs)
- Incident response and forensics
- Network security and intrusion detection

Always respond with accurate, actionable intelligence. Structure your responses clearly.
When referencing MITRE techniques, use the format T#### (e.g., T1566 for Phishing).
Be concise but thorough. Flag critical findings prominently."""


def chat(message: str, history: list[dict]) -> str:
    messages = history + [{"role": "user", "content": message}]
    response = client.messages.create(
        model=settings.CLAUDE_MODEL,
        max_tokens=settings.MAX_TOKENS,
        system=SYSTEM_PROMPT,
        messages=messages,
    )
    return response.content[0].text


def analyze_ioc(indicator: str, ioc_type: str, context: str | None) -> str:
    context_section = f"\nAdditional context: {context}" if context else ""
    prompt = f"""Analyze this Indicator of Compromise (IOC):

Type: {ioc_type}
Indicator: {indicator}{context_section}

Provide a structured analysis including:
1. Severity assessment (critical/high/medium/low/info)
2. Threat intelligence summary
3. Known threat actors or malware families associated (if any)
4. MITRE ATT&CK techniques (T#### format)
5. Recommended defensive actions (as a list)

Format your response as JSON with keys: severity, analysis, recommendations (list), mitre_techniques (list)"""

    response = client.messages.create(
        model=settings.CLAUDE_MODEL,
        max_tokens=settings.MAX_TOKENS,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": prompt}],
    )
    return response.content[0].text


def analyze_cve(cve_id: str, context: str | None) -> str:
    context_section = f"\nEnvironment context: {context}" if context else ""
    prompt = f"""Analyze this CVE vulnerability:

CVE ID: {cve_id}{context_section}

Provide a structured analysis including:
1. Severity (critical/high/medium/low/info)
2. Technical analysis of the vulnerability
3. Affected systems and versions (as a list)
4. Remediation steps (as a list)
5. Exploitability assessment (actively exploited / PoC available / theoretical)

Format your response as JSON with keys: severity, analysis, affected_systems (list), remediation (list), exploitability"""

    response = client.messages.create(
        model=settings.CLAUDE_MODEL,
        max_tokens=settings.MAX_TOKENS,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": prompt}],
    )
    return response.content[0].text


def analyze_malware(sample_info: str, behavior: str | None) -> str:
    behavior_section = f"\nObserved behavior:\n{behavior}" if behavior else ""
    prompt = f"""Analyze this malware sample:

Sample info: {sample_info}{behavior_section}

Provide a structured analysis including:
1. Malware classification (ransomware, trojan, RAT, etc.)
2. Severity (critical/high/medium/low/info)
3. Technical analysis
4. Extracted IOCs (as a list)
5. MITRE ATT&CK techniques (T#### format, as a list)
6. Containment and remediation recommendations (as a list)

Format your response as JSON with keys: classification, severity, analysis, iocs (list), mitre_techniques (list), recommendations (list)"""

    response = client.messages.create(
        model=settings.CLAUDE_MODEL,
        max_tokens=settings.MAX_TOKENS,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": prompt}],
    )
    return response.content[0].text


def analyze_threat_report(raw_data: str, environment: str | None) -> str:
    env_section = f"\nEnvironment: {environment}" if environment else ""
    prompt = f"""Analyze the following threat data and generate an intelligence report:{env_section}

Raw data:
{raw_data}

Provide:
1. Executive summary
2. Overall severity (critical/high/medium/low/info)
3. Key findings (as a list)
4. MITRE ATT&CK techniques observed (T#### format, as a list)
5. Prioritized recommendations (as a list)

Format your response as JSON with keys: summary, severity, findings (list), mitre_techniques (list), recommendations (list)"""

    response = client.messages.create(
        model=settings.CLAUDE_MODEL,
        max_tokens=settings.MAX_TOKENS,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": prompt}],
    )
    return response.content[0].text
