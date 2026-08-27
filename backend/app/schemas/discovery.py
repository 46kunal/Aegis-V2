from pydantic import BaseModel, field_validator
import ipaddress


class DiscoverAssetsRequest(BaseModel):
    cidr: str

    @field_validator("cidr")
    @classmethod
    def validate_cidr(cls, value: str) -> str:
        try:
            ipaddress.ip_network(value, strict=False)
        except ValueError as exc:
            raise ValueError("Invalid CIDR range") from exc
        return value


class DiscoveredDevice(BaseModel):
    ip: str
    hostname: str | None = None
    mac: str | None = None
    status: str


class DiscoverAssetsResponse(BaseModel):
    cidr: str
    discovered_count: int
    devices: list[DiscoveredDevice]
