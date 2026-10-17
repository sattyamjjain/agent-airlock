"""Synthetic tools for the fix_hints recovery benchmark, and the ``@Airlock`` stubs that guard them.

Every tool is a plain Python function with typed parameters (``Annotated`` with ``Field``
constraints, ``Literal``), wrapped by ``@Airlock`` with the configuration its scenario
names (:func:`build_stub`). The bodies do nothing: a call that passes every gate records
itself and returns :data:`CANARY_PREFIX` plus the tool name, so "the corrected call ran"
is observable with no side effect (:func:`invoke`).

Names are fictional and namespaced. Filesystem roots live under ``/airlock-bench/``, a
directory that does not exist, so no path resolves through a symlink and no refusal can
carry the local working directory or home directory. Hosts use the reserved ``.example``
TLD or ``example.com`` / ``.org`` / ``.net`` (RFC 2606).

Every stub runs with ``UnknownArgsMode.BLOCK``, not the default ``STRIP_AND_LOG``: an
argument a corrected call invents is refused rather than silently stripped, so
"recovered" means the call satisfied the whole contract.
"""

from __future__ import annotations

import contextvars
import functools
import inspect
import json
import operator
import os
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Annotated, Any, Literal, get_type_hints

from pydantic import Field, create_model

from agent_airlock import Airlock, AirlockConfig
from agent_airlock.capabilities import Capability, CapabilityPolicy, requires
from agent_airlock.filesystem import FilesystemPolicy
from agent_airlock.network import EndpointPolicy
from agent_airlock.policy import SecurityPolicy
from agent_airlock.unknown_args import UnknownArgsMode

CANARY_PREFIX = "AIRLOCK_FH_RAN:"
"""What a tool body returns when a call reached it: this prefix plus the tool's name."""

TOOLS: dict[str, Callable[..., str]] = {}
"""Tool name -> function, in definition order."""

_CALLS: contextvars.ContextVar[list[tuple[str, dict[str, Any]]] | None] = contextvars.ContextVar(
    "fix_hints_calls", default=None
)


def _tool(fn: Callable[..., str]) -> Callable[..., str]:
    if fn.__name__ in TOOLS:
        raise ValueError(f"duplicate tool name {fn.__name__!r}")
    TOOLS[fn.__name__] = fn
    return fn


def _ran(name: str, **arguments: Any) -> str:
    """Record that ``name``'s body ran with ``arguments`` and return its canary."""
    calls = _CALLS.get()
    if calls is not None:
        calls.append((name, dict(arguments)))
    return CANARY_PREFIX + name


# --------------------------------------------------------------------------------------
# Base tools: every parameter required, one per JSON type the type-mismatch categories
# exercise. The missing-argument, ghost-argument and multi-error categories reuse them.
# --------------------------------------------------------------------------------------


@_tool
def get_forecast(
    city: Annotated[str, Field(description="City name")],
    days: Annotated[int, Field(description="Number of days to forecast")],
) -> str:
    """Return the weather forecast for a city."""
    return _ran("get_forecast", city=city, days=days)


@_tool
def search_tickets(
    query: Annotated[str, Field(description="Text to search for")],
    limit: Annotated[int, Field(description="Maximum number of tickets to return")],
) -> str:
    """Search support tickets, most recent first."""
    return _ran("search_tickets", query=query, limit=limit)


@_tool
def add_to_cart(
    sku: Annotated[str, Field(description="Product SKU")],
    quantity: Annotated[int, Field(description="Number of units to add")],
) -> str:
    """Add units of a product to the shopping cart."""
    return _ran("add_to_cart", sku=sku, quantity=quantity)


@_tool
def set_timer(
    label: Annotated[str, Field(description="Timer label")],
    minutes: Annotated[int, Field(description="Duration in minutes")],
) -> str:
    """Start a countdown timer."""
    return _ran("set_timer", label=label, minutes=minutes)


@_tool
def book_room(
    room: Annotated[str, Field(description="Meeting room name")],
    date: Annotated[str, Field(description="Date, YYYY-MM-DD")],
    attendees: Annotated[int, Field(description="Number of attendees")],
) -> str:
    """Book a meeting room for a day."""
    return _ran("book_room", room=room, date=date, attendees=attendees)


@_tool
def lookup_zip(
    zip_code: Annotated[str, Field(description="Postal code")],
    country: Annotated[str, Field(description="Country code, e.g. US")],
) -> str:
    """Look up the town for a postal code."""
    return _ran("lookup_zip", zip_code=zip_code, country=country)


@_tool
def get_order_status(
    order_id: Annotated[str, Field(description="Order number")],
    include_items: Annotated[bool, Field(description="Include the list of items")],
) -> str:
    """Return the status of an order."""
    return _ran("get_order_status", order_id=order_id, include_items=include_items)


@_tool
def install_package(
    package: Annotated[str, Field(description="Package name")],
    version: Annotated[str, Field(description="Exact version to install")],
) -> str:
    """Install a specific version of a package."""
    return _ran("install_package", package=package, version=version)


@_tool
def dial_extension(
    extension: Annotated[str, Field(description="Phone extension to dial")],
    line: Annotated[str, Field(description="Outgoing line to dial from")],
) -> str:
    """Dial an internal phone extension."""
    return _ran("dial_extension", extension=extension, line=line)


@_tool
def lookup_employee(
    employee_id: Annotated[str, Field(description="Employee number")],
    department: Annotated[str, Field(description="Department name")],
) -> str:
    """Look up an employee record."""
    return _ran("lookup_employee", employee_id=employee_id, department=department)


@_tool
def send_report(
    report: Annotated[str, Field(description="Report name")],
    notify_team: Annotated[bool, Field(description="Notify the team when it is sent")],
) -> str:
    """Send a report to its distribution list."""
    return _ran("send_report", report=report, notify_team=notify_team)


@_tool
def list_files(
    folder: Annotated[str, Field(description="Folder name in the shared drive")],
    recursive: Annotated[bool, Field(description="Include subfolders")],
) -> str:
    """List the files in a shared-drive folder."""
    return _ran("list_files", folder=folder, recursive=recursive)


@_tool
def deploy_service(
    service: Annotated[str, Field(description="Service name")],
    dry_run: Annotated[bool, Field(description="Simulate the deploy without applying it")],
) -> str:
    """Deploy the latest build of a service."""
    return _ran("deploy_service", service=service, dry_run=dry_run)


@_tool
def create_event(
    title: Annotated[str, Field(description="Event title")],
    date: Annotated[str, Field(description="Date, YYYY-MM-DD")],
    all_day: Annotated[bool, Field(description="Whether the event lasts all day")],
) -> str:
    """Create a calendar event."""
    return _ran("create_event", title=title, date=date, all_day=all_day)


@_tool
def search_archive(
    query: Annotated[str, Field(description="Text to search for")],
    include_archived: Annotated[bool, Field(description="Also search archived documents")],
) -> str:
    """Search the document store."""
    return _ran("search_archive", query=query, include_archived=include_archived)


@_tool
def set_thermostat(
    zone: Annotated[str, Field(description="Heating zone")],
    celsius: Annotated[float, Field(description="Target temperature in degrees Celsius")],
) -> str:
    """Set a thermostat's target temperature."""
    return _ran("set_thermostat", zone=zone, celsius=celsius)


@_tool
def log_hours(
    project: Annotated[str, Field(description="Project name")],
    hours: Annotated[float, Field(description="Hours worked")],
) -> str:
    """Log time worked against a project."""
    return _ran("log_hours", project=project, hours=hours)


@_tool
def scale_image(
    image_id: Annotated[str, Field(description="Image identifier")],
    factor: Annotated[float, Field(description="Scale factor")],
) -> str:
    """Resize an image by a scale factor."""
    return _ran("scale_image", image_id=image_id, factor=factor)


@_tool
def set_playback_speed(
    track_id: Annotated[str, Field(description="Track identifier")],
    speed: Annotated[float, Field(description="Playback speed multiplier")],
) -> str:
    """Set the playback speed of a track."""
    return _ran("set_playback_speed", track_id=track_id, speed=speed)


@_tool
def record_weight(
    parcel_id: Annotated[str, Field(description="Parcel identifier")],
    kilograms: Annotated[float, Field(description="Weight in kilograms")],
) -> str:
    """Record the weight of a parcel."""
    return _ran("record_weight", parcel_id=parcel_id, kilograms=kilograms)


@_tool
def tag_ticket(
    ticket_id: Annotated[str, Field(description="Ticket identifier")],
    tags: Annotated[list[str], Field(description="Tags to add")],
) -> str:
    """Add tags to a support ticket."""
    return _ran("tag_ticket", ticket_id=ticket_id, tags=tags)


@_tool
def invite_attendees(
    event_id: Annotated[str, Field(description="Event identifier")],
    emails: Annotated[list[str], Field(description="Email addresses to invite")],
) -> str:
    """Invite people to an event."""
    return _ran("invite_attendees", event_id=event_id, emails=emails)


@_tool
def compare_cities(
    cities: Annotated[list[str], Field(description="Cities to compare")],
    metric: Annotated[str, Field(description="What to compare")],
) -> str:
    """Compare a metric across cities."""
    return _ran("compare_cities", cities=cities, metric=metric)


@_tool
def restock(
    warehouse: Annotated[str, Field(description="Warehouse name")],
    skus: Annotated[list[str], Field(description="Product SKUs to restock")],
) -> str:
    """Request a restock of products at a warehouse."""
    return _ran("restock", warehouse=warehouse, skus=skus)


@_tool
def subscribe_topics(
    user_id: Annotated[str, Field(description="User identifier")],
    topics: Annotated[list[str], Field(description="Notification topics")],
) -> str:
    """Subscribe a user to notification topics."""
    return _ran("subscribe_topics", user_id=user_id, topics=topics)


@_tool
def label_resource(
    resource_id: Annotated[str, Field(description="Cloud resource identifier")],
    labels: Annotated[dict[str, str], Field(description="Labels to set, as key-value pairs")],
) -> str:
    """Set labels on a cloud resource."""
    return _ran("label_resource", resource_id=resource_id, labels=labels)


@_tool
def set_env_vars(
    service: Annotated[str, Field(description="Service name")],
    variables: Annotated[dict[str, str], Field(description="Environment variables to set")],
) -> str:
    """Set environment variables on a service."""
    return _ran("set_env_vars", service=service, variables=variables)


@_tool
def update_profile(
    user_id: Annotated[str, Field(description="User identifier")],
    changes: Annotated[dict[str, str], Field(description="Profile fields to change")],
) -> str:
    """Update fields on a user profile."""
    return _ran("update_profile", user_id=user_id, changes=changes)


@_tool
def filter_records(
    table: Annotated[str, Field(description="Table name")],
    filters: Annotated[dict[str, str], Field(description="Column filters, column to value")],
) -> str:
    """Return the rows of a table that match every filter."""
    return _ran("filter_records", table=table, filters=filters)


@_tool
def set_product_attributes(
    sku: Annotated[str, Field(description="Product SKU")],
    attributes: Annotated[dict[str, str], Field(description="Attributes to set")],
) -> str:
    """Set attributes on a product."""
    return _ran("set_product_attributes", sku=sku, attributes=attributes)


# --------------------------------------------------------------------------------------
# Constraint tools: numeric bounds, string length, Literal values.
# --------------------------------------------------------------------------------------


@_tool
def set_volume(
    device: Annotated[str, Field(description="Speaker name")],
    level: Annotated[float, Field(ge=0, le=1, description="Volume level")],
) -> str:
    """Set a speaker's volume."""
    return _ran("set_volume", device=device, level=level)


@_tool
def set_sample_rate(
    stream: Annotated[str, Field(description="Event stream name")],
    rate: Annotated[float, Field(gt=0, le=1, description="Share of events to keep")],
) -> str:
    """Set the sampling rate of an event stream."""
    return _ran("set_sample_rate", stream=stream, rate=rate)


@_tool
def set_request_timeout(
    service: Annotated[str, Field(description="Service name")],
    timeout_ms: Annotated[int, Field(ge=100, le=600000, description="Timeout in milliseconds")],
) -> str:
    """Set a service's request timeout."""
    return _ran("set_request_timeout", service=service, timeout_ms=timeout_ms)


@_tool
def allocate_cpu(
    service: Annotated[str, Field(description="Service name")],
    millicores: Annotated[int, Field(ge=100, le=16000, description="CPU in millicores")],
) -> str:
    """Set a service's CPU allocation."""
    return _ran("allocate_cpu", service=service, millicores=millicores)


@_tool
def set_memory_limit(
    service: Annotated[str, Field(description="Service name")],
    megabytes: Annotated[int, Field(ge=128, le=65536, description="Memory limit in megabytes")],
) -> str:
    """Set a service's memory limit."""
    return _ran("set_memory_limit", service=service, megabytes=megabytes)


@_tool
def get_page(
    collection: Annotated[str, Field(description="Collection to page through")],
    page: Annotated[int, Field(ge=1, description="Page number")],
) -> str:
    """Return one page of a collection."""
    return _ran("get_page", collection=collection, page=page)


@_tool
def remove_from_cart(
    sku: Annotated[str, Field(description="Product SKU")],
    quantity: Annotated[int, Field(gt=0, description="Number of units to remove")],
) -> str:
    """Remove units of a product from the shopping cart."""
    return _ran("remove_from_cart", sku=sku, quantity=quantity)


@_tool
def set_retry_jitter(
    service: Annotated[str, Field(description="Service name")],
    jitter: Annotated[float, Field(ge=0, lt=1, description="Retry jitter")],
) -> str:
    """Set the random jitter applied to a service's retry delays."""
    return _ran("set_retry_jitter", service=service, jitter=jitter)


@_tool
def ship_order(
    order_id: Annotated[str, Field(description="Order number")],
    country_code: Annotated[str, Field(max_length=2, description="Destination country code")],
) -> str:
    """Ship an order to a country."""
    return _ran("ship_order", order_id=order_id, country_code=country_code)


@_tool
def quote_price(
    sku: Annotated[str, Field(description="Product SKU")],
    currency: Annotated[str, Field(max_length=3, description="Currency code")],
) -> str:
    """Quote a product's price in a currency."""
    return _ran("quote_price", sku=sku, currency=currency)


@_tool
def create_ticket(
    title: Annotated[str, Field(max_length=40, description="Ticket title")],
    description: Annotated[str, Field(description="Ticket description")],
) -> str:
    """Open a support ticket."""
    return _ran("create_ticket", title=title, description=description)


@_tool
def search_flights(
    origin: Annotated[str, Field(max_length=3, description="Origin airport code")],
    destination: Annotated[str, Field(max_length=3, description="Destination airport code")],
    date: Annotated[str, Field(description="Departure date, YYYY-MM-DD")],
) -> str:
    """Search for flights on a date."""
    return _ran("search_flights", origin=origin, destination=destination, date=date)


@_tool
def set_sku_label(
    sku: Annotated[str, Field(max_length=8, description="Product SKU")],
    label: Annotated[str, Field(description="Shelf label")],
) -> str:
    """Set the shelf label shown for a product."""
    return _ran("set_sku_label", sku=sku, label=label)


@_tool
def post_status(
    team: Annotated[str, Field(description="Team name")],
    headline: Annotated[str, Field(max_length=60, description="Status headline")],
) -> str:
    """Post a team's status headline."""
    return _ran("post_status", team=team, headline=headline)


@_tool
def set_priority(
    ticket_id: Annotated[str, Field(description="Ticket identifier")],
    priority: Annotated[Literal["low", "normal", "high", "urgent"], Field(description="Priority")],
) -> str:
    """Set a support ticket's priority."""
    return _ran("set_priority", ticket_id=ticket_id, priority=priority)


@_tool
def get_weather(
    city: Annotated[str, Field(description="City name")],
    units: Annotated[Literal["metric", "imperial"], Field(description="Unit system")],
) -> str:
    """Return the current weather for a city."""
    return _ran("get_weather", city=city, units=units)


@_tool
def search_posts(
    query: Annotated[str, Field(description="Text to search for")],
    order: Annotated[Literal["asc", "desc"], Field(description="Sort order by publication date")],
) -> str:
    """Search blog posts."""
    return _ran("search_posts", query=query, order=order)


@_tool
def export_report(
    report_id: Annotated[str, Field(description="Report identifier")],
    file_format: Annotated[Literal["csv", "xlsx", "pdf"], Field(description="Export format")],
) -> str:
    """Export a report as a file."""
    return _ran("export_report", report_id=report_id, file_format=file_format)


@_tool
def set_visibility(
    doc_id: Annotated[str, Field(description="Document identifier")],
    visibility: Annotated[
        Literal["private", "team", "public"], Field(description="Who can see it")
    ],
) -> str:
    """Set who can see a document."""
    return _ran("set_visibility", doc_id=doc_id, visibility=visibility)


@_tool
def set_log_level(
    service: Annotated[str, Field(description="Service name")],
    level: Annotated[Literal["debug", "info", "warning", "error"], Field(description="Log level")],
) -> str:
    """Set a service's log level."""
    return _ran("set_log_level", service=service, level=level)


# --------------------------------------------------------------------------------------
# Filesystem tools. Their path parameter is a plain ``str``: SafePath refuses a plain str
# under strict mode, so the refusal would be a type error rather than the path gate's.
# --------------------------------------------------------------------------------------


@_tool
def read_file(path: Annotated[str, Field(description="Path of the file to read")]) -> str:
    """Read a text file."""
    return _ran("read_file", path=path)


@_tool
def list_directory(path: Annotated[str, Field(description="Directory to list")]) -> str:
    """List the entries of a directory."""
    return _ran("list_directory", path=path)


@_tool
def get_file_info(path: Annotated[str, Field(description="Path of the file")]) -> str:
    """Return a file's size and last-modified time."""
    return _ran("get_file_info", path=path)


@_tool
def search_file(
    path: Annotated[str, Field(description="Path of the file to search")],
    pattern: Annotated[str, Field(description="Text to look for")],
) -> str:
    """Return the lines of a file that contain a pattern."""
    return _ran("search_file", path=path, pattern=pattern)


@_tool
def append_note(
    path: Annotated[str, Field(description="Path of the notes file")],
    text: Annotated[str, Field(description="Line to append")],
) -> str:
    """Append a line to a notes file."""
    return _ran("append_note", path=path, text=text)


# --------------------------------------------------------------------------------------
# Network tools, each checked against its own endpoint allowlist.
# --------------------------------------------------------------------------------------


@_tool
def fetch_url(url: Annotated[str, Field(description="URL to fetch")]) -> str:
    """Fetch a URL with GET and return the response body."""
    return _ran("fetch_url", url=url)


@_tool
def get_json(url: Annotated[str, Field(description="URL of a JSON resource")]) -> str:
    """Fetch a JSON resource."""
    return _ran("get_json", url=url)


@_tool
def download_report(
    url: Annotated[str, Field(description="URL of the report")],
    save_as: Annotated[str, Field(description="File name to save it under")],
) -> str:
    """Download a report file."""
    return _ran("download_report", url=url, save_as=save_as)


@_tool
def post_webhook(
    url: Annotated[str, Field(description="Webhook URL")],
    message: Annotated[str, Field(description="Message text")],
) -> str:
    """Post a message to a chat webhook."""
    return _ran("post_webhook", url=url, message=message)


@_tool
def check_status(url: Annotated[str, Field(description="Status endpoint URL")]) -> str:
    """Check a health endpoint."""
    return _ran("check_status", url=url)


# --------------------------------------------------------------------------------------
# Policy controls: a forbidden tool and the permitted alternative some scenarios offer.
# --------------------------------------------------------------------------------------


@_tool
def delete_branch(
    repo: Annotated[str, Field(description="Repository name")],
    branch: Annotated[str, Field(description="Branch name")],
) -> str:
    """Delete a branch from a repository."""
    return _ran("delete_branch", repo=repo, branch=branch)


@_tool
def archive_branch(
    repo: Annotated[str, Field(description="Repository name")],
    branch: Annotated[str, Field(description="Branch name")],
) -> str:
    """Archive a branch: hide it from listings, keep its history."""
    return _ran("archive_branch", repo=repo, branch=branch)


@_tool
def drop_table(
    database: Annotated[str, Field(description="Database name")],
    table: Annotated[str, Field(description="Table name")],
) -> str:
    """Drop a database table."""
    return _ran("drop_table", database=database, table=table)


@_tool
def archive_table(
    database: Annotated[str, Field(description="Database name")],
    table: Annotated[str, Field(description="Table name")],
) -> str:
    """Move a table to cold storage, keeping its data."""
    return _ran("archive_table", database=database, table=table)


@_tool
def delete_user_account(user_id: Annotated[str, Field(description="User identifier")]) -> str:
    """Delete a user account and its data."""
    return _ran("delete_user_account", user_id=user_id)


@_tool
def deactivate_user_account(user_id: Annotated[str, Field(description="User identifier")]) -> str:
    """Deactivate a user account so it can no longer sign in."""
    return _ran("deactivate_user_account", user_id=user_id)


@_tool
def purge_cache(
    service: Annotated[str, Field(description="Service name")],
    region: Annotated[str, Field(description="Region")],
) -> str:
    """Delete every entry in a service's cache."""
    return _ran("purge_cache", service=service, region=region)


@_tool
def refresh_cache(
    service: Annotated[str, Field(description="Service name")],
    region: Annotated[str, Field(description="Region")],
) -> str:
    """Re-fetch stale entries in a service's cache."""
    return _ran("refresh_cache", service=service, region=region)


@_tool
def force_push(
    repo: Annotated[str, Field(description="Repository name")],
    branch: Annotated[str, Field(description="Branch name")],
) -> str:
    """Force-push a local branch, overwriting the remote branch."""
    return _ran("force_push", repo=repo, branch=branch)


@_tool
def push_branch(
    repo: Annotated[str, Field(description="Repository name")],
    branch: Annotated[str, Field(description="Branch name")],
) -> str:
    """Push a local branch to the remote."""
    return _ran("push_branch", repo=repo, branch=branch)


@_tool
def deploy_to_production(
    service: Annotated[str, Field(description="Service name")],
    version: Annotated[str, Field(description="Version to deploy")],
) -> str:
    """Deploy a version of a service to production."""
    return _ran("deploy_to_production", service=service, version=version)


@_tool
def deploy_to_staging(
    service: Annotated[str, Field(description="Service name")],
    version: Annotated[str, Field(description="Version to deploy")],
) -> str:
    """Deploy a version of a service to staging."""
    return _ran("deploy_to_staging", service=service, version=version)


@_tool
def wipe_bucket(bucket: Annotated[str, Field(description="Bucket name")]) -> str:
    """Delete every object in a storage bucket."""
    return _ran("wipe_bucket", bucket=bucket)


@_tool
def archive_bucket(bucket: Annotated[str, Field(description="Bucket name")]) -> str:
    """Move a storage bucket's objects to archival storage."""
    return _ran("archive_bucket", bucket=bucket)


# --------------------------------------------------------------------------------------
# Capability controls: tools that declare a capability with @requires.
# --------------------------------------------------------------------------------------


@_tool
@requires(Capability.PROCESS_SHELL)
def run_shell(command: Annotated[str, Field(description="Shell command to run")]) -> str:
    """Run a shell command on the build host."""
    return _ran("run_shell", command=command)


@_tool
@requires(Capability.PROCESS_EXEC)
def execute_python(code: Annotated[str, Field(description="Python source to execute")]) -> str:
    """Execute a Python snippet and return its output."""
    return _ran("execute_python", code=code)


@_tool
@requires(Capability.FILESYSTEM_DELETE)
def delete_path(target: Annotated[str, Field(description="File or folder to delete")]) -> str:
    """Delete a file or folder."""
    return _ran("delete_path", target=target)


@_tool
@requires(Capability.NETWORK_ARBITRARY)
def open_socket(
    host: Annotated[str, Field(description="Host name")],
    port: Annotated[int, Field(description="TCP port")],
    payload: Annotated[str, Field(description="Bytes to send, as text")],
) -> str:
    """Open a raw TCP connection, send a payload and return the reply."""
    return _ran("open_socket", host=host, port=port, payload=payload)


@_tool
@requires(Capability.DATABASE_WRITE)
def write_database(statement: Annotated[str, Field(description="SQL statement to run")]) -> str:
    """Run a write statement against the orders database."""
    return _ran("write_database", statement=statement)


# --------------------------------------------------------------------------------------
# Stubs
# --------------------------------------------------------------------------------------


def _capabilities(names: Any) -> Capability:
    flags = [Capability[str(name)] for name in names or ()]
    return functools.reduce(operator.or_, flags, Capability.NONE)


def build_config(spec: Mapping[str, Any]) -> AirlockConfig:
    """The ``AirlockConfig`` a scenario's config spec describes.

    Spec keys (all optional): ``filesystem_roots`` (list of roots), ``endpoints``
    (tool name -> allowed hosts) and ``capability`` (``granted`` / ``denied`` lists of
    :class:`Capability` names). Audit logging is off and unknown arguments are refused.

    Raises:
        RuntimeError: An environment variable overrode ``unknown_args``.
    """
    kwargs: dict[str, Any] = {"unknown_args": UnknownArgsMode.BLOCK, "enable_audit_log": False}
    roots = spec.get("filesystem_roots")
    if roots:
        kwargs["filesystem_policy"] = FilesystemPolicy(allowed_roots=[Path(r) for r in roots])
    endpoints = spec.get("endpoints")
    if endpoints:
        kwargs["endpoint_policies"] = {
            tool: EndpointPolicy(allowed_endpoints=list(hosts)) for tool, hosts in endpoints.items()
        }
    capability = spec.get("capability")
    if capability:
        kwargs["capability_policy"] = CapabilityPolicy(
            granted=_capabilities(capability.get("granted")),
            denied=_capabilities(capability.get("denied")),
        )
    config = AirlockConfig(**kwargs)
    if config.unknown_args is not UnknownArgsMode.BLOCK:
        raise RuntimeError(
            "AIRLOCK_UNKNOWN_ARGS or AIRLOCK_STRICT_MODE in the environment overrides "
            "unknown_args=BLOCK; unset it, or the ghost-argument scenarios do not refuse"
        )
    return config


def build_policy(spec: Mapping[str, Any]) -> SecurityPolicy | None:
    """A fresh ``SecurityPolicy`` from the spec's ``policy`` key, or None."""
    policy = spec.get("policy")
    if not policy:
        return None
    return SecurityPolicy(
        allowed_tools=list(policy.get("allowed_tools") or []),
        denied_tools=list(policy.get("denied_tools") or []),
    )


def build_stub(tool: str, spec: Mapping[str, Any]) -> Callable[..., Any]:
    """A fresh ``@Airlock`` wrapper around ``tool`` with the spec's config and policy."""
    return Airlock(config=build_config(spec), policy=build_policy(spec))(TOOLS[tool])


def invoke(
    tool: str, spec: Mapping[str, Any], arguments: Mapping[str, Any]
) -> tuple[Any, list[tuple[str, dict[str, Any]]]]:
    """Call a fresh stub of ``tool`` with ``arguments`` as keyword arguments.

    Returns:
        ``(result, calls)``: the stub's return value (a canary string when the body
        ran, ``AirlockResponse.to_dict()`` when airlock refused) and the bodies that ran.
    """
    calls: list[tuple[str, dict[str, Any]]] = []
    token = _CALLS.set(calls)
    try:
        result = build_stub(tool, spec)(**dict(arguments))
    finally:
        _CALLS.reset(token)
    return result, calls


def is_refusal(result: Any) -> bool:
    """Whether ``result`` is airlock's refusal dict (``success`` False, ``status`` blocked)."""
    return (
        isinstance(result, dict)
        and result.get("success") is False
        and result.get("status") == "blocked"
    )


def ran(tool: str, result: Any, calls: list[tuple[str, dict[str, Any]]]) -> bool:
    """Whether the call reached ``tool``'s body: the canary came back and was recorded."""
    return result == CANARY_PREFIX + tool and [name for name, _ in calls] == [tool]


def refusal_detail(result: Mapping[str, Any]) -> tuple[str, ...]:
    """What a refusal is about beyond its ``block_reason``, read from stable metadata.

    ``field:type`` pairs for a validation error, the ghost argument names, the path
    violation type, the endpoint reason, or the refused tool for a policy violation. A
    capability refusal carries no metadata today, so its detail is empty. Hint text is
    never read, so a change to the hints cannot change a scenario's identity.
    """
    reason = result.get("block_reason")
    metadata = result.get("metadata") or {}
    if reason == "validation_error":
        errors = metadata.get("errors") or []
        return tuple(
            sorted(f"{e.get('field')}:{e.get('type')}" for e in errors if isinstance(e, Mapping))
        )
    if reason == "ghost_arguments":
        return tuple(sorted(str(name) for name in metadata.get("ghost_arguments") or []))
    if reason == "path_violation":
        return (str(metadata.get("violation_type")),)
    if reason == "endpoint_blocked":
        return (str(metadata.get("block_reason")),)
    if reason == "policy_violation":
        return (str(metadata.get("function")),)
    return ()


def _local_paths() -> set[str]:
    paths: set[str] = set()
    for raw in (os.getcwd(), str(Path.home())):
        for form in (raw, os.path.realpath(raw)):
            if len(form) > 1:
                paths.add(form)
    return paths


def leaks_local_path(result: Any) -> bool:
    """Whether a refusal carries this machine's working or home directory.

    A payload that did would leak a local path to the API and change with the machine
    it was generated on, which breaks the R1/R2 payload comparison.
    """
    text = json.dumps(result, default=str)
    return any(path in text for path in _local_paths())


# --------------------------------------------------------------------------------------
# JSON schemas for the Messages API ``tools`` parameter
# --------------------------------------------------------------------------------------


def _strip_titles(node: Any) -> Any:
    """Drop the ``title`` keys pydantic adds to schema nodes; keep property names."""
    if isinstance(node, dict):
        out: dict[str, Any] = {}
        for key, value in node.items():
            if key == "title" and isinstance(value, str):
                continue
            if key in {"properties", "$defs"} and isinstance(value, dict):
                out[key] = {name: _strip_titles(sub) for name, sub in value.items()}
            else:
                out[key] = _strip_titles(value)
        return out
    if isinstance(node, list):
        return [_strip_titles(value) for value in node]
    return node


def tool_description(tool: str) -> str:
    """The first paragraph of the tool's docstring."""
    doc = inspect.getdoc(TOOLS[tool]) or tool
    return doc.split("\n\n", 1)[0].strip()


@functools.cache
def _schema_json(tool: str) -> str:
    fn = TOOLS[tool]
    hints = get_type_hints(fn, include_extras=True)
    fields: dict[str, Any] = {}
    for name, param in inspect.signature(fn).parameters.items():
        default = ... if param.default is inspect.Parameter.empty else param.default
        fields[name] = (hints[name], default)
    model = create_model(f"{tool}_input", **fields)
    definition = {
        "name": tool,
        "description": tool_description(tool),
        "input_schema": _strip_titles(model.model_json_schema()),
    }
    return json.dumps(definition)


def tool_schema(tool: str) -> dict[str, Any]:
    """The tool's Messages API definition, its input schema built from its signature.

    No ``strict`` flag: the model sees the schema as ordinary tools publish it. Built
    once per tool; each call returns a fresh copy.
    """
    return dict(json.loads(_schema_json(tool)))


def required_parameters(tool: str) -> list[str]:
    """The tool's parameters that have no default, in signature order."""
    return [
        name
        for name, param in inspect.signature(TOOLS[tool]).parameters.items()
        if param.default is inspect.Parameter.empty
    ]


def parameter_types(tool: str) -> dict[str, Any]:
    """Parameter name -> annotation with ``Annotated`` metadata removed."""
    return get_type_hints(TOOLS[tool])
