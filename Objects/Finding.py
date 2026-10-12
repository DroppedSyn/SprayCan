import uuid

class Finding:
    def __init__(
        self,
        title="",
        desc="",
        severity="info",
        confidence="medium",
        objects=None,
        evidence=None,
        rec="",
        meta=None,
    ):
        self.id = str(uuid.uuid4())
        self.title = title
        self.desc = desc
        self.severity = severity
        self.confidence = confidence
        self.objects = objects if objects is not None else []
        self.evidence = evidence if evidence is not None else []
        self.rec = rec
        self.meta = meta if meta is not None else {}

    def to_dict(self):
        return {
            "id": self.id,
            "title": self.title,
            "desc": self.desc,
            "severity": self.severity,
            "confidence": self.confidence,
            "objects": self.objects,
            "evidence": self.evidence,
            "rec": self.rec,
            "meta": self.meta,
        }
