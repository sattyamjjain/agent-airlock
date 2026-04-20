"""MCP Proxy Security Guard for Agent-Airlock (V0.4.0).

Implements MCP security best practices for proxy servers:
- Token passthrough prevention (tokens should be scoped, not forwarded)
- Session binding (user_id, session_id tracking)
- Consent hooks for sensitive operations

Based on MCP Security Best Practices:
https://modelcontextprotocol.io/specification/draft/basic/security_best_practices

The problem with token passthrough:
    When an MCP proxy forwards tokens from clients to downstream servers,
    it creates a credential chain that's hard to audit and easy to exploit.
    Attackers can use the proxy as a "credential laundry" to access
    downstream services with stolen tokens.

This module helps MCP server authors:
1. Validate that tokens are scoped to their service (not passthrough)
2. Bind sessions to user identity for audit trails
3. Require explicit consent for sensitive tool access
"""

from __future__ import annotations

import secrets
import time
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

import structlog

from .policy import StdioGuardConfig

if TYPE_CHECKING:
    from .mcp_spec.oauth_audit import OAuthAppAuditConfig, OAuthAuditReport

logger = structlog.get_logger("agent-airlock.mcp_proxy_guard")


class MCPSecurityError(Exception):
    """Raised when an MCP security check fails."""

    def __init__(
        self,
        message: str,
        violation_type: str = "security_violation",
        details: dict[str, Any] | None = None,
    ) -> None:
        self.message = message
        self.violation_type = violation_type
        self.details = details or {}
        super().__init__(message)


@dataclass
class MCPSession:
    """Represents an MCP session with bound identity.

    Attributes:
        session_id: Unique session identifier.
        user_id: User identifier (from authentication).
        created_at: Timestamp when session was created.
        last_activity: Timestamp of last activity.
        consented_tools: Tools the user has consented to.
        metadata: Additional session metadata.
    """

    session_id: str
    user_id: str | None = None
    created_at: float = field(default_factory=time.time)
    last_activity: float = field(default_factory=time.time)
    consented_tools: set[str] = field(default_factory=set)
    metadata: dict[str, Any] = field(default_factory=dict)

    def touch(self) -> None:
        """Update last activity timestamp."""
        self.last_activity = time.time()

    def add_consent(self, tool_name: str) -> None:
        """Add consent for a tool."""
        self.consented_tools.add(tool_name)

    def has_consent(self, tool_name: str) -> bool:
        """Check if consent exists for a tool."""
        return tool_name in self.consented_tools

    def is_expired(self, max_age_seconds: int = 3600) -> bool:
        """Check if session has expired."""
        return time.time() - self.last_activity > max_age_seconds


@dataclass
class MCPProxyConfig:
    """Configuration for MCP proxy security.

    Attributes:
        block_token_passthrough: If True, reject requests that appear to be
            passing through tokens to downstream services.
        required_token_audience: If set, tokens must have this audience claim.
        required_token_issuer: If set, tokens must have this issuer claim.
        bind_to_session: If True, track and bind requests to sessions.
        session_id_header: HTTP header for session ID.
        rotate_session_on_auth: If True, rotate session ID after authentication.
        max_session_age_seconds: Maximum session age before expiry.
        require_consent_for_tools: Tools that require explicit user consent.
        passthrough_header_denylist: Headers that indicate token passthrough.
    """

    # Token handling
    block_token_passthrough: bool = True
    required_token_audience: str | None = None
    required_token_issuer: str | None = None

    # Session binding
    bind_to_session: bool = True
    session_id_header: str = "X-MCP-Session-ID"
    rotate_session_on_auth: bool = True
    max_session_age_seconds: int = 3600

    # Consent
    require_consent_for_tools: list[str] = field(default_factory=list)

    # Passthrough detection
    passthrough_header_denylist: list[str] = field(
        default_factory=lambda: [
            "X-Original-Authorization",
            "X-Forwarded-Authorization",
            "X-Upstream-Token",
            "X-Backend-Token",
        ]
    )

    # V0.4.1 Per-tool credential scopes
    tool_scopes: dict[str, CredentialScope] = field(default_factory=dict)

    # V0.5.1 Ox MCP STDIO sanitizer. When set, ``MCPProxyGuard``
    # exposes ``validate_stdio_spawn()`` which callers must invoke
    # before any ``subprocess.Popen`` for a STDIO transport. See
    # ``agent_airlock.policy.StdioGuardConfig`` and
    # ``agent_airlock.policy_presets.stdio_guard_ox_defaults``.
    stdio_guard: StdioGuardConfig | None = None

    # V0.5.2 OAuth audit guard (Vercel/Context.ai 2026-04-19). When
    # set, ``MCPProxyGuard.audit_oauth_exchange()`` delegates to
    # ``agent_airlock.mcp_spec.oauth_audit.audit_oauth_exchange`` with
    # this config. Default None preserves v0.5.1 behavior.
    oauth_audit: OAuthAppAuditConfig | None = None


@dataclass
class CredentialScope:
    """Declares minimum credential requirements for a tool.

    Used to enforce least-privilege: if a tool only needs read access
    to storage, the scope declaration makes this explicit and auditable.

    Example:
        scope = CredentialScope(
            required_scopes=["storage.read", "keyvault.list"],
            max_token_age_seconds=300,
            allowed_audiences=["https://management.azure.com"],
        )

    Attributes:
        required_scopes: Scopes the token must have (checked against 'scp' or 'scope' claim).
        max_token_age_seconds: Reject tokens older than this. Default 3600 (1 hour).
        require_fresh_token: If True, token must be <60s old (checked via 'iat' claim).
        allowed_audiences: If set, token 'aud' claim must match one of these.
    """

    required_scopes: list[str] = field(default_factory=list)
    max_token_age_seconds: int = 3600
    require_fresh_token: bool = False
    allowed_audiences: list[str] = field(default_factory=list)


class MCPProxyGuard:
    """Security guard for MCP proxy servers.

    Implements MCP security best practices:
    - No token passthrough (tokens should be scoped, not forwarded)
    - Session binding (user_id, session_id tracking)
    - Consent hooks for sensitive tools

    Usage:
        guard = MCPProxyGuard(MCPProxyConfig(
            required_token_audience="my-mcp-server",
            require_consent_for_tools=["delete_*", "write_*"],
        ))

        # In your MCP server request handler:
        try:
            guard.validate_request(request)
            session = guard.get_or_create_session(request)
            # ... handle request ...
        except MCPSecurityError as e:
            return error_response(e.message)
    """

    def __init__(self, config: MCPProxyConfig | None = None) -> None:
        """Initialize the proxy guard.

        Args:
            config: Guard configuration. Defaults to MCPProxyConfig().
        """
        self.config = config or MCPProxyConfig()
        self._sessions: dict[str, MCPSession] = {}

    def validate_request(self, request: dict[str, Any]) -> None:
        """Validate an incoming MCP request.

        Checks for:
        - Token passthrough (forwarding tokens to downstream)
        - Session binding (if enabled)
        - Token audience/issuer (if configured)

        Args:
            request: The incoming request with headers.

        Raises:
            MCPSecurityError: If validation fails.
        """
        headers = request.get("headers", {})

        # Check for passthrough headers
        if self.config.block_token_passthrough:
            self._check_passthrough_headers(headers)

        # Check authorization token
        auth_header = headers.get("Authorization") or headers.get("authorization")
        if auth_header:
            self._validate_token(auth_header)

        # Check session binding
        if self.config.bind_to_session:
            session_id = headers.get(self.config.session_id_header)
            if not session_id:
                raise MCPSecurityError(
                    f"Missing session ID header: {self.config.session_id_header}",
                    violation_type="missing_session",
                )

    def _check_passthrough_headers(self, headers: dict[str, str]) -> None:
        """Check for headers that indicate token passthrough."""
        for header in self.config.passthrough_header_denylist:
            if header in headers or header.lower() in {h.lower() for h in headers}:
                raise MCPSecurityError(
                    f"Token passthrough detected via header: {header}. "
                    "Tokens should be scoped to this proxy, not forwarded to downstream services.",
                    violation_type="token_passthrough",
                    details={"header": header},
                )

    def _validate_token(self, auth_header: str) -> None:
        """Validate the authorization token."""
        # Extract token from Bearer prefix if present
        token = auth_header
        if auth_header.lower().startswith("bearer "):
            token = auth_header[7:]

        # Check if it's a JWT and validate audience/issuer
        if self.config.required_token_audience or self.config.required_token_issuer:
            if not self._validate_jwt_claims(token):
                raise MCPSecurityError(
                    "Token validation failed. Token does not have required audience/issuer claims.",
                    violation_type="invalid_token",
                )

    def _validate_jwt_claims(self, token: str) -> bool:
        """Validate JWT audience and issuer claims."""
        try:
            # Try to decode without verification (just checking claims)
            import jwt

            decoded = jwt.decode(token, options={"verify_signature": False})

            if self.config.required_token_audience:
                aud = decoded.get("aud")
                # aud can be string or list
                if isinstance(aud, list):
                    if self.config.required_token_audience not in aud:
                        logger.warning(
                            "token_audience_mismatch",
                            expected=self.config.required_token_audience,
                            actual=aud,
                        )
                        return False
                elif aud != self.config.required_token_audience:
                    logger.warning(
                        "token_audience_mismatch",
                        expected=self.config.required_token_audience,
                        actual=aud,
                    )
                    return False

            if self.config.required_token_issuer:
                iss = decoded.get("iss")
                if iss != self.config.required_token_issuer:
                    logger.warning(
                        "token_issuer_mismatch",
                        expected=self.config.required_token_issuer,
                        actual=iss,
                    )
                    return False

            return True

        except ImportError:
            logger.warning(
                "pyjwt_not_installed",
                hint="Install PyJWT for token validation: pip install PyJWT",
            )
            return True  # Allow if can't validate
        except Exception as e:
            logger.warning("token_decode_failed", error=str(e))
            return False

    def get_or_create_session(
        self,
        request: dict[str, Any],
        user_id: str | None = None,
    ) -> MCPSession:
        """Get existing session or create a new one.

        Args:
            request: The request with session ID header.
            user_id: User ID to bind to the session.

        Returns:
            MCPSession instance.
        """
        headers = request.get("headers", {})
        session_id = headers.get(self.config.session_id_header)

        if session_id and session_id in self._sessions:
            session = self._sessions[session_id]
            if not session.is_expired(self.config.max_session_age_seconds):
                session.touch()
                # Update user_id if provided and different
                if user_id and session.user_id != user_id:
                    if self.config.rotate_session_on_auth:
                        # Rotate session on identity change
                        return self._create_new_session(user_id)
                    session.user_id = user_id
                return session

        # Create new session
        return self._create_new_session(user_id)

    def _create_new_session(self, user_id: str | None = None) -> MCPSession:
        """Create a new session."""
        session_id = secrets.token_urlsafe(32)
        session = MCPSession(session_id=session_id, user_id=user_id)
        self._sessions[session_id] = session

        logger.info(
            "session_created",
            session_id=session_id[:8] + "...",
            user_id=user_id,
        )

        return session

    def check_tool_consent(
        self,
        session: MCPSession,
        tool_name: str,
    ) -> bool:
        """Check if a tool requires consent and if consent has been given.

        Args:
            session: The current session.
            tool_name: The tool being invoked.

        Returns:
            True if consent is given or not required.

        Raises:
            MCPSecurityError: If consent is required but not given.
        """
        import fnmatch

        for pattern in self.config.require_consent_for_tools:
            if fnmatch.fnmatch(tool_name, pattern):
                if not session.has_consent(tool_name):
                    raise MCPSecurityError(
                        f"Tool '{tool_name}' requires explicit consent. "
                        "Call grant_consent() to approve this tool.",
                        violation_type="consent_required",
                        details={"tool": tool_name, "pattern": pattern},
                    )

        return True

    def grant_consent(
        self,
        session: MCPSession,
        tool_name: str,
    ) -> None:
        """Grant consent for a tool in a session.

        Args:
            session: The session to grant consent for.
            tool_name: The tool to consent to.
        """
        session.add_consent(tool_name)
        logger.info(
            "consent_granted",
            session_id=session.session_id[:8] + "...",
            tool_name=tool_name,
        )

    def validate_tool_credentials(
        self,
        tool_name: str,
        token: str | None = None,
        token_claims: dict[str, Any] | None = None,
    ) -> None:
        """Validate that credentials meet the tool's scope requirements.

        Checks:
        - Required scopes are present in token claims
        - Token age is within max_token_age_seconds
        - Token audience matches allowed_audiences
        - Token freshness (if require_fresh_token is True)

        Args:
            tool_name: Name of the tool being called.
            token: JWT token string (decoded if token_claims not provided).
            token_claims: Pre-decoded token claims dict.

        Raises:
            MCPSecurityError: If validation fails.

        Example:
            guard.validate_tool_credentials(
                "azure_query",
                token_claims={"scp": "storage.read keyvault.list", "aud": "..."},
            )
        """
        scope = self.get_tool_scope(tool_name)
        if scope is None:
            return  # No scope declared, pass freely

        # Get claims from token or use provided claims
        claims = token_claims
        if claims is None and token is not None:
            claims = self._decode_token_claims(token)

        if claims is None:
            if scope.required_scopes:
                logger.warning(
                    "credential_scope_validation_failed",
                    tool_name=tool_name,
                    reason="no_token_provided",
                )
                raise MCPSecurityError(
                    f"Tool '{tool_name}' requires credentials but no token was provided",
                    violation_type="missing_credentials",
                    details={"tool": tool_name, "required_scopes": scope.required_scopes},
                )
            return

        # Check required scopes
        if scope.required_scopes:
            token_scopes = self._extract_scopes(claims)
            missing_scopes = [s for s in scope.required_scopes if s not in token_scopes]
            if missing_scopes:
                logger.warning(
                    "credential_scope_validation_failed",
                    tool_name=tool_name,
                    reason="missing_scopes",
                    missing=missing_scopes,
                )
                raise MCPSecurityError(
                    f"Token missing required scopes for '{tool_name}': {missing_scopes}",
                    violation_type="insufficient_scopes",
                    details={
                        "tool": tool_name,
                        "missing_scopes": missing_scopes,
                        "required_scopes": scope.required_scopes,
                        "token_scopes": list(token_scopes),
                    },
                )

        # Check token age
        iat = claims.get("iat")
        if iat is not None:
            token_age = time.time() - float(iat)
            if token_age > scope.max_token_age_seconds:
                logger.warning(
                    "credential_scope_validation_failed",
                    tool_name=tool_name,
                    reason="token_expired",
                    token_age_seconds=round(token_age),
                    max_age=scope.max_token_age_seconds,
                )
                raise MCPSecurityError(
                    f"Token too old for '{tool_name}': "
                    f"{round(token_age)}s > {scope.max_token_age_seconds}s",
                    violation_type="token_expired",
                    details={
                        "tool": tool_name,
                        "token_age_seconds": round(token_age),
                        "max_token_age_seconds": scope.max_token_age_seconds,
                    },
                )

            # Check freshness requirement
            if scope.require_fresh_token and token_age > 60:
                logger.warning(
                    "credential_scope_validation_failed",
                    tool_name=tool_name,
                    reason="token_not_fresh",
                    token_age_seconds=round(token_age),
                )
                raise MCPSecurityError(
                    f"Token not fresh enough for '{tool_name}': {round(token_age)}s old (max 60s)",
                    violation_type="token_not_fresh",
                    details={
                        "tool": tool_name,
                        "token_age_seconds": round(token_age),
                        "max_fresh_seconds": 60,
                    },
                )

        # Check audience
        if scope.allowed_audiences:
            aud = claims.get("aud")
            aud_list = [aud] if isinstance(aud, str) else (aud or [])
            if not any(a in scope.allowed_audiences for a in aud_list):
                logger.warning(
                    "credential_scope_validation_failed",
                    tool_name=tool_name,
                    reason="audience_mismatch",
                    token_aud=aud_list,
                    allowed=scope.allowed_audiences,
                )
                raise MCPSecurityError(
                    f"Token audience mismatch for '{tool_name}'",
                    violation_type="audience_mismatch",
                    details={
                        "tool": tool_name,
                        "token_audience": aud_list,
                        "allowed_audiences": scope.allowed_audiences,
                    },
                )

        logger.info(
            "credential_scope_validated",
            tool_name=tool_name,
            scopes_checked=len(scope.required_scopes),
        )

    def get_tool_scope(self, tool_name: str) -> CredentialScope | None:
        """Get the declared credential scope for a tool.

        Args:
            tool_name: Name of the tool.

        Returns:
            CredentialScope if declared, None otherwise.
        """
        return self.config.tool_scopes.get(tool_name)

    @staticmethod
    def _extract_scopes(claims: dict[str, Any]) -> set[str]:
        """Extract scopes from token claims.

        Checks 'scp' (space-separated string) and 'scope' (string or list) claims.
        """
        scopes: set[str] = set()
        # Azure AD uses 'scp' as space-separated string
        scp = claims.get("scp", "")
        if isinstance(scp, str) and scp:
            scopes.update(scp.split())
        # Some providers use 'scope'
        scope_claim = claims.get("scope", "")
        if isinstance(scope_claim, str) and scope_claim:
            scopes.update(scope_claim.split())
        elif isinstance(scope_claim, list):
            scopes.update(scope_claim)
        return scopes

    @staticmethod
    def _decode_token_claims(token: str) -> dict[str, Any] | None:
        """Decode JWT token claims without signature verification."""
        try:
            import jwt

            return jwt.decode(token, options={"verify_signature": False})  # type: ignore[no-any-return]
        except ImportError:
            logger.warning(
                "pyjwt_not_installed",
                hint="Install PyJWT for token validation: pip install PyJWT",
            )
            return None
        except Exception as e:
            logger.warning("token_decode_failed", error=str(e))
            return None

    def audit_oauth_exchange(
        self,
        token_response: dict[str, Any],
        client_id: str,
    ) -> OAuthAuditReport:
        """Audit an OAuth token exchange against the configured policy.

        Call this immediately after a successful token exchange via
        ``agent_airlock.mcp_spec.oauth`` and before caching the
        token. Mitigates the 2026-04-19 Vercel / Context.ai
        compromised-OAuth-app class by rejecting known-compromised
        client IDs, oversize token lifetimes, missing PKCE evidence,
        and refresh-token reuse.

        Args:
            token_response: The JSON body of the token endpoint
                response.
            client_id: The OAuth client_id that initiated the exchange.

        Returns:
            ``OAuthAuditReport`` on success.

        Raises:
            MCPSecurityError: If no ``oauth_audit`` is configured.
            OAuthAppBlocked: The client_id is on the deny-list.
            OAuthPolicyViolation: Token response violated the policy
                (missing PKCE, stale refresh, oversize lifetime, etc.).
        """
        if self.config.oauth_audit is None:
            raise MCPSecurityError(
                "oauth_audit is not configured on this MCPProxyGuard",
                violation_type="oauth_audit_not_configured",
            )
        from .mcp_spec.oauth_audit import audit_oauth_exchange

        return audit_oauth_exchange(token_response, client_id, self.config.oauth_audit)

    def validate_stdio_spawn(self, cmd: list[str]) -> None:
        """Validate a STDIO-transport spawn against the configured guard.

        Call this immediately before ``subprocess.Popen(cmd, shell=False)``
        when the Popen is being driven by an MCP STDIO transport (i.e. you
        are spawning an MCP server subprocess because an mcp.json entry
        told you to). Mitigates the Ox Security 2026-04 advisory class.

        Args:
            cmd: argv list, as for ``subprocess.Popen(args=[...])``.

        Raises:
            MCPSecurityError: If no ``stdio_guard`` is configured.
            StdioInjectionError: If the argv fails any sanitiser rule.
                Subclass of ``agent_airlock.exceptions.AirlockError``.
        """
        if self.config.stdio_guard is None:
            raise MCPSecurityError(
                "stdio_guard is not configured on this MCPProxyGuard",
                violation_type="stdio_guard_not_configured",
            )
        # Local import to avoid a top-level cycle (stdio_guard imports
        # StdioGuardConfig from policy.py, but is itself inside mcp_spec/).
        from .mcp_spec.stdio_guard import validate_stdio_command

        validate_stdio_command(cmd, self.config.stdio_guard)

    def cleanup_expired_sessions(self) -> int:
        """Remove expired sessions.

        Returns:
            Number of sessions removed.
        """
        expired = [
            sid
            for sid, session in self._sessions.items()
            if session.is_expired(self.config.max_session_age_seconds)
        ]

        for sid in expired:
            del self._sessions[sid]

        if expired:
            logger.info("sessions_cleaned_up", count=len(expired))

        return len(expired)

    def get_session_count(self) -> int:
        """Get the number of active sessions."""
        return len(self._sessions)


# Predefined configurations
DEFAULT_PROXY_CONFIG = MCPProxyConfig()
"""Default configuration with passthrough blocking enabled."""

STRICT_PROXY_CONFIG = MCPProxyConfig(
    block_token_passthrough=True,
    bind_to_session=True,
    rotate_session_on_auth=True,
    max_session_age_seconds=1800,  # 30 minutes
    require_consent_for_tools=["delete_*", "write_*", "exec_*", "shell_*"],
)
"""Strict configuration for high-security environments."""

PERMISSIVE_PROXY_CONFIG = MCPProxyConfig(
    block_token_passthrough=False,
    bind_to_session=False,
)
"""Permissive configuration for development/testing."""
