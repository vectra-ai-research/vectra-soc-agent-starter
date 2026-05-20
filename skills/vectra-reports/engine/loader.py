"""Discover and validate YAML report definitions.

Identical schema to the MCP server's report engine — drop-in compatible YAML.
The only behavioural change is that ``definitions_dir()`` resolves relative to
the skill repo, and ``id`` validation surfaces parse errors via stderr rather
than a logger.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Annotated, Any, Literal, Optional, Union

import yaml
from pydantic import BaseModel, Field, ValidationError, field_validator, model_validator

_ID_RE = re.compile(r"^[a-z0-9_]+$")


class ReportParameter(BaseModel):
    name: str
    type: Literal["int", "str", "bool"]
    description: str = ""
    default: Any = None
    required: bool = False


class PaginationModel(BaseModel):
    enabled: bool = True
    max_pages: int = 10
    page_size: int = 50

    @field_validator("max_pages")
    @classmethod
    def _max_pages_positive(cls, v: int) -> int:
        return max(1, v)

    @field_validator("page_size")
    @classmethod
    def _page_size_range(cls, v: int) -> int:
        return max(1, min(10_000, v))


class InvestigationDataSource(BaseModel):
    type: Literal["investigation_query"] = "investigation_query"
    id: str
    query: str
    parameters: dict[str, str] = Field(default_factory=dict)
    pagination: PaginationModel = Field(default_factory=PaginationModel)


class VectraRestDataSource(BaseModel):
    type: Literal["vectra_rest"] = "vectra_rest"
    id: str
    client_method: str
    parameters: dict[str, str] = Field(default_factory=dict)
    arguments: dict[str, str] = Field(default_factory=dict)


DataSource = Annotated[
    Union[InvestigationDataSource, VectraRestDataSource],
    Field(discriminator="type"),
]


class SummaryMetric(BaseModel):
    label: str
    value_field: str
    aggregation: Literal["count", "sum", "max", "min"] = "count"
    format: Literal["number", "bytes", "duration"] = "number"


class TableColumn(BaseModel):
    field: str
    label: str
    format: Literal[
        "text", "bytes", "timestamp", "ip", "number", "hash", "percent", "duration"
    ] = "text"


class SectionDefinition(BaseModel):
    id: str
    title: str
    type: Literal["summary", "table", "chart"]
    data_source: str
    metrics: list[SummaryMetric] = Field(default_factory=list)
    columns: list[TableColumn] = Field(default_factory=list)
    chart_type: Optional[Literal["pie", "bar", "line", "sankey"]] = None
    label_field: str = ""
    value_field: str = ""
    dst_field: str = ""
    row_limit: int = 500
    empty_message: str = "No results for this time period."

    @model_validator(mode="after")
    def _check_section(self) -> SectionDefinition:
        if self.type == "summary" and not self.metrics:
            raise ValueError(f"summary section {self.id!r} requires metrics")
        if self.type == "table" and not self.columns:
            raise ValueError(f"table section {self.id!r} requires columns")
        if self.type == "chart":
            if self.chart_type is None:
                raise ValueError(f"chart section {self.id!r} requires chart_type")
            if self.chart_type in ("bar", "line"):
                raise ValueError(
                    f"chart section {self.id!r}: chart_type {self.chart_type!r} "
                    "is not implemented"
                )
            if self.chart_type == "pie" and not (
                self.label_field.strip() and self.value_field.strip()
            ):
                raise ValueError(
                    f"chart section {self.id!r} requires label_field and value_field"
                )
            if self.chart_type == "sankey" and not (
                self.label_field.strip()
                and self.dst_field.strip()
                and self.value_field.strip()
            ):
                raise ValueError(
                    f"sankey section {self.id!r} requires label_field, dst_field, "
                    "and value_field"
                )
        return self


class OutputModel(BaseModel):
    default_format: Literal["html", "markdown", "json"] = "html"
    title_template: str = "{{ name }}"
    include_metadata: bool = True


class ReportDefinition(BaseModel):
    id: str
    name: str
    description: str = ""
    category: str = "General"
    version: str = "1.0"
    parameters: list[ReportParameter] = Field(default_factory=list)
    data_sources: list[DataSource]
    sections: list[SectionDefinition]
    output: OutputModel = Field(default_factory=OutputModel)

    @field_validator("id")
    @classmethod
    def _id_pattern(cls, v: str) -> str:
        if not _ID_RE.match(v):
            raise ValueError(
                "report id must match ^[a-z0-9_]+$ (used in CLI: run_report.py <id>)"
            )
        return v

    @model_validator(mode="after")
    def _unique_source_ids(self) -> ReportDefinition:
        ids = [ds.id for ds in self.data_sources]
        if len(ids) != len(set(ids)):
            raise ValueError("data_sources must have unique id values")
        return self

    @model_validator(mode="after")
    def _section_refs(self) -> ReportDefinition:
        known = {ds.id for ds in self.data_sources}
        for sec in self.sections:
            if sec.data_source not in known:
                raise ValueError(
                    f"section {sec.id!r} references unknown data_source "
                    f"{sec.data_source!r}"
                )
        return self


def definitions_dir() -> Path:
    """Default location of YAML report definitions inside the skill repo."""
    return Path(__file__).resolve().parent.parent / "definitions"


def load_report_definitions(
    root: Optional[Path] = None,
    *,
    quiet: bool = False,
) -> list[ReportDefinition]:
    """Load every ``*.yaml`` under ``definitions/`` (broken files skipped, logged to stderr)."""
    base = root or definitions_dir()
    if not base.is_dir():
        if not quiet:
            print(
                f"warning: definitions directory not found: {base}", file=sys.stderr
            )
        return []
    out: list[ReportDefinition] = []
    for path in sorted(base.glob("*.yaml")):
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                if not quiet:
                    print(
                        f"warning: skipping {path.name}: root must be a mapping",
                        file=sys.stderr,
                    )
                continue
            out.append(ReportDefinition.model_validate(data))
        except (ValidationError, yaml.YAMLError, OSError) as exc:
            if not quiet:
                print(
                    f"warning: invalid report definition {path.name}: {exc}",
                    file=sys.stderr,
                )
    return out


def find_report(
    report_id: str, root: Optional[Path] = None
) -> Optional[ReportDefinition]:
    """Return a single report by id, or None if not found."""
    for defn in load_report_definitions(root, quiet=True):
        if defn.id == report_id:
            return defn
    return None
