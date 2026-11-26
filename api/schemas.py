"""Pydantic request schemas for the Brand Impersonation Hunter API."""

from typing import Dict, List, Optional
from pydantic import BaseModel, Field


class ScanRequest(BaseModel):
    target: str
    include_logos: bool = True
    probe_subdomains: bool = True
    save_icons: bool = True
    timeout: int = Field(12, ge=2, le=60)


class BatchRequest(BaseModel):
    targets: List[str]
    include_logos: bool = True
    probe_subdomains: bool = True
    timeout: int = Field(10, ge=2, le=60)


class ImageAnalysisRequest(BaseModel):
    image_url: Optional[str] = None
    image_base64: Optional[str] = None
    compare_phash: Optional[str] = None
    timeout: int = Field(12, ge=2, le=60)


class BulkImageAnalysisRequest(BaseModel):
    image_urls: List[str] = []
    images_base64: List[dict] = []
    compare_phash: Optional[str] = None
    timeout: int = Field(12, ge=2, le=60)


class AggregateHashesRequest(BaseModel):
    input_text: str


class LaunchEnginesRequest(BaseModel):
    urls: List[str]


class ImpersonationDorksRequest(BaseModel):
    keywords: str
    include_variants: bool = False


class ImpersonationCaptureRequest(BaseModel):
    keywords: str
    include_variants: bool = False
    use_ct: bool = True
    use_intel: bool = True
    use_feeds: bool = True
    use_dns: bool = False


class DomainEvaluateRequest(BaseModel):
    """Offline impersonation analysis of a list of hostnames (no network unless `resolve` is set)."""
    original_domain: str
    keywords: List[str] = Field(default_factory=list, max_length=200)
    domains: List[str] = Field(default_factory=list, max_length=50000)
    allowlist: List[str] = Field(default_factory=list, max_length=200)
    include_benign: bool = False
    resolve: bool = False


class HuntRequest(BaseModel):
    target: str
    depth: str = "standard"
    use_ct: bool = True
    verify: bool = True
    use_rdap: bool = True
    use_intel: bool = True
    use_feeds: bool = True
    allowlist: List[str] = Field(default_factory=list)
    keywords: List[str] = Field(default_factory=list)
    timeout: int = Field(8, ge=3, le=30)
    max_verify: int = Field(400, ge=10, le=2000)


class DailyIntelRequest(BaseModel):
    target: str
    brand_title: Optional[str] = None
    keywords: List[str] = Field(default_factory=list)
    allowlist: List[str] = Field(default_factory=list)
    lookback_hours: int = Field(24, ge=1, le=336)
    include_urlscan: bool = True
    include_ct: bool = True
    include_feeds: bool = True
    include_dns: bool = True
    include_whoisxml: bool = False
    with_typos: bool = True
    timeout: int = Field(8, ge=3, le=30)


class SaveKeysRequest(BaseModel):
    values: Dict[str, str]


class TestKeyRequest(BaseModel):
    source: str
    values: Dict[str, str] = Field(default_factory=dict)
    key_id: Optional[str] = None
    all: bool = False


class KeyRefRequest(BaseModel):
    name: str
    id: str


class AddKeyRequest(BaseModel):
    name: str
    value: str


class ResetRequest(BaseModel):
    source: Optional[str] = None


class TriageRequest(BaseModel):
    brand: str
    domain: str
    status: str
    note: str = ""


class WatchRequest(BaseModel):
    brand: str
    depth: str = "standard"
    interval_hours: int = Field(24, ge=1, le=24 * 30)
    min_score: int = Field(45, ge=0, le=100)
    webhook_url: str = ""
    allowlist: List[str] = Field(default_factory=list)


class WatchPatch(BaseModel):
    enabled: Optional[bool] = None
    depth: Optional[str] = None
    interval_hours: Optional[int] = Field(None, ge=1, le=24 * 30)
    min_score: Optional[int] = Field(None, ge=0, le=100)
    webhook_url: Optional[str] = None


class ReadRequest(BaseModel):
    id: Optional[int] = None


class StorageUriRequest(BaseModel):
    uri: Optional[str] = None
    db: Optional[str] = None


class MigrateRequest(BaseModel):
    direction: str = "from_sqlite"


# ---------------------------------------------------------------------------- Scan Scheduler & Data Management
class ScheduleSpec(BaseModel):
    frequency: str = "daily"
    time: Optional[str] = Field("02:00", max_length=5)
    timezone: Optional[str] = Field("UTC", max_length=64)
    weekdays: Optional[List[int]] = Field(None, max_length=7)
    interval_hours: Optional[float] = Field(None, ge=1, le=24 * 30)


class NotifySpec(BaseModel):
    in_app: bool = True
    on_new: bool = True
    on_failure: bool = True
    min_classification: str = "potential"
    webhook_url: Optional[str] = Field(None, max_length=2000)


class DomainEntry(BaseModel):
    domain: str = Field(..., max_length=2048)
    organization: Optional[str] = Field("", max_length=200)
    keywords: List[str] = Field(default_factory=list, max_length=60)


class BatchCreateRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=120)
    description: Optional[str] = Field("", max_length=1000)
    organization: Optional[str] = Field("", max_length=200)
    schedule: ScheduleSpec = Field(default_factory=ScheduleSpec)
    depth: str = "standard"
    missed_policy: str = "run_once"
    status: str = "active"
    notify: NotifySpec = Field(default_factory=NotifySpec)
    domains: List[DomainEntry] = Field(default_factory=list, max_length=1000)


class BatchPatchRequest(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=120)
    description: Optional[str] = Field(None, max_length=1000)
    organization: Optional[str] = Field(None, max_length=200)
    schedule: Optional[ScheduleSpec] = None
    depth: Optional[str] = None
    missed_policy: Optional[str] = None
    notify: Optional[NotifySpec] = None


class BatchStatusRequest(BaseModel):
    status: str


class BatchDomainsRequest(BaseModel):
    entries: List[DomainEntry] = Field(default_factory=list, max_length=1000)


class DomainIdsRequest(BaseModel):
    domain_ids: List[str] = Field(default_factory=list, max_length=1000)
    confirm: Optional[str] = Field(None, max_length=300)


class ParseDomainsRequest(BaseModel):
    text: Optional[str] = Field(None, max_length=2_000_000)
    filename: Optional[str] = Field(None, max_length=255)
    content_b64: Optional[str] = Field(None, max_length=3_000_000)
    batch_id: Optional[str] = Field(None, max_length=40)


class DomainPatchRequest(BaseModel):
    keywords: Optional[List[str]] = Field(None, max_length=60)
    allowlist: Optional[List[str]] = Field(None, max_length=100)
    organization: Optional[str] = Field(None, max_length=200)
    depth: Optional[str] = None
    status: Optional[str] = None


class DomainRunRequest(BaseModel):
    batch_id: Optional[str] = Field(None, max_length=40)


class FindingReviewRequest(BaseModel):
    ids: List[str] = Field(default_factory=list, max_length=1000)
    under_review: bool = True


class SchedulerSettingsRequest(BaseModel):
    enabled: Optional[bool] = None
    concurrency: Optional[int] = None
    max_parallel_executions: Optional[int] = None
    job_timeout: Optional[int] = None
    max_attempts: Optional[int] = None
    retry_base_seconds: Optional[int] = None


class ConfirmRequest(BaseModel):
    confirm: str = Field("", max_length=300)


class DeleteFindingsRequest(BaseModel):
    confirm: str = Field("", max_length=300)
    ids: Optional[List[str]] = Field(None, max_length=5000)
    all: bool = False


class DeleteBatchRequest(BaseModel):
    confirm: str = Field("", max_length=300)
    delete_exclusive_domains: bool = False


class DeleteDomainRequest(BaseModel):
    confirm: str = Field("", max_length=300)
    cancel_active: bool = False
