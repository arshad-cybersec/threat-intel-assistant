import json
from fastapi import APIRouter, HTTPException
from app.models.schemas import (
    IOCRequest, IOCResponse,
    CVERequest, CVEResponse,
    MalwareRequest, MalwareResponse,
    ThreatReportRequest, ThreatReportResponse,
    SeverityLevel,
)
from app.services import claude_service

router = APIRouter()


def parse_json_response(raw: str) -> dict:
    """Strip markdown fences and parse JSON from Claude's response."""
    clean = raw.strip()
    if clean.startswith("```"):
        clean = clean.split("```")[1]
        if clean.startswith("json"):
            clean = clean[4:]
    return json.loads(clean.strip())


@router.post("/ioc", response_model=IOCResponse)
async def analyze_ioc(request: IOCRequest):
    """
    Analyze an Indicator of Compromise (IP, domain, URL, file hash, email).
    Returns severity, threat intel, MITRE techniques, and recommendations.
    """
    try:
        raw = claude_service.analyze_ioc(request.indicator, request.ioc_type, request.context)
        data = parse_json_response(raw)
        return IOCResponse(
            indicator=request.indicator,
            ioc_type=request.ioc_type,
            severity=SeverityLevel(data.get("severity", "info")),
            analysis=data.get("analysis", ""),
            recommendations=data.get("recommendations", []),
            mitre_techniques=data.get("mitre_techniques", []),
        )
    except json.JSONDecodeError:
        raise HTTPException(status_code=502, detail="Failed to parse AI response as JSON")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/cve", response_model=CVEResponse)
async def analyze_cve(request: CVERequest):
    """
    Analyze a CVE vulnerability.
    Returns severity, affected systems, remediation steps, and exploitability.
    """
    try:
        raw = claude_service.analyze_cve(request.cve_id, request.context)
        data = parse_json_response(raw)
        return CVEResponse(
            cve_id=request.cve_id,
            severity=SeverityLevel(data.get("severity", "info")),
            analysis=data.get("analysis", ""),
            affected_systems=data.get("affected_systems", []),
            remediation=data.get("remediation", []),
            exploitability=data.get("exploitability", "Unknown"),
        )
    except json.JSONDecodeError:
        raise HTTPException(status_code=502, detail="Failed to parse AI response as JSON")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/malware", response_model=MalwareResponse)
async def analyze_malware(request: MalwareRequest):
    """
    Analyze a malware sample by hash, filename, or behavioral description.
    Returns classification, IOCs, MITRE techniques, and containment steps.
    """
    try:
        raw = claude_service.analyze_malware(request.sample_info, request.behavior)
        data = parse_json_response(raw)
        return MalwareResponse(
            classification=data.get("classification", "Unknown"),
            severity=SeverityLevel(data.get("severity", "high")),
            analysis=data.get("analysis", ""),
            iocs=data.get("iocs", []),
            mitre_techniques=data.get("mitre_techniques", []),
            recommendations=data.get("recommendations", []),
        )
    except json.JSONDecodeError:
        raise HTTPException(status_code=502, detail="Failed to parse AI response as JSON")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/report", response_model=ThreatReportResponse)
async def generate_threat_report(request: ThreatReportRequest):
    """
    Generate a threat intelligence report from raw logs, alerts, or threat data.
    Returns executive summary, findings, MITRE techniques, and prioritized actions.
    """
    try:
        raw = claude_service.analyze_threat_report(request.raw_data, request.environment)
        data = parse_json_response(raw)
        return ThreatReportResponse(
            summary=data.get("summary", ""),
            severity=SeverityLevel(data.get("severity", "medium")),
            findings=data.get("findings", []),
            mitre_techniques=data.get("mitre_techniques", []),
            recommendations=data.get("recommendations", []),
        )
    except json.JSONDecodeError:
        raise HTTPException(status_code=502, detail="Failed to parse AI response as JSON")
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
