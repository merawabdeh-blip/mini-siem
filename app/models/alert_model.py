from pydantic import BaseModel

class Alert(BaseModel):
    source_ip: str
    attack_type: str
    severity: str
