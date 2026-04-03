from pydantic import BaseModel

class Log(BaseModel):
    source_ip: str
    event_type: str
    severity: str
    message: str
    status: str
