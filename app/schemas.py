from datetime import datetime
from pydantic import BaseModel, ConfigDict, Field


class ResolveCodeRequest(BaseModel):
    key: str = Field(min_length=8, max_length=256)


class ResolveCodeResponse(BaseModel):
    code: str
    received_at: datetime
    source_label: str
    ttl_hint: int


class LoginCodeItem(BaseModel):
    code: str
    received_at: datetime
    subject: str | None = None


class LoginCodeListResponse(BaseModel):
    ok: bool
    feature: str
    total: int
    items: list[LoginCodeItem]


class FamilyLinkResponse(BaseModel):
    ok: bool
    feature: str
    url: str
    code: str | None = None
    received_at: datetime
    subject: str | None = None


class ApiError(BaseModel):
    error: str
    message: str
    ttl_hint: int | None = None


class MailboxCreate(BaseModel):
    label: str
    email_full: str
    app_password: str
    imap_server: str = "imap.gmail.com"
    imap_port: int = 993
    active: bool = True


class MailboxOut(BaseModel):
    id: int
    label: str
    email_masked: str
    imap_server: str
    imap_port: int
    active: bool

    model_config = ConfigDict(from_attributes=True)


class MailboxUpdate(BaseModel):
    label: str | None = None
    email_full: str | None = None
    app_password: str | None = None
    imap_server: str | None = None
    imap_port: int | None = None
    active: bool | None = None


class ParserRuleCreate(BaseModel):
    name: str
    code_type: str
    regex_patterns: list[str]
    sender_filter: str | None = None
    subject_filter: str | None = None
    time_window_minutes: int = 60
    active: bool = True


class ParserRuleOut(BaseModel):
    id: int
    name: str
    code_type: str
    regex_patterns: list[str]
    sender_filter: str | None
    subject_filter: str | None
    time_window_minutes: int
    active: bool

    model_config = ConfigDict(from_attributes=True)


class ParserRuleUpdate(BaseModel):
    name: str | None = None
    code_type: str | None = None
    regex_patterns: list[str] | None = None
    sender_filter: str | None = None
    subject_filter: str | None = None
    time_window_minutes: int | None = None
    active: bool | None = None


class AccessKeyCreate(BaseModel):
    key_plain: str = Field(min_length=8, max_length=256)
    key_label: str
    mailbox_id: int
    parser_rule_id: int
    active: bool = True


class AccessKeyOut(BaseModel):
    id: int
    key_label: str
    mailbox_id: int
    parser_rule_id: int
    active: bool
    last_resolved_at: datetime | None

    model_config = ConfigDict(from_attributes=True)


class AccessKeyUpdate(BaseModel):
    key_label: str | None = None
    mailbox_id: int | None = None
    parser_rule_id: int | None = None
    active: bool | None = None
