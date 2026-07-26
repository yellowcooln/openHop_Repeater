import logging

import cherrypy

logger = logging.getLogger("HTTPServer")


def check_auth():
    """
    CherryPy tool to check authentication before processing request.

    Checks for a JWT in Authorization, an API token in X-API-Key, or a one-time
    endpoint-bound stream ticket in the query string.
    Sets cherrypy.request.user on success.
    Returns 401 JSON response on failure.
    """
    # Terminate CORS preflight before CherryPy dispatches the protected handler.
    if cherrypy.request.method == "OPTIONS":
        cherrypy.response.status = 204
        cherrypy.request.handler = None
        return

    # Skip auth check for /auth/login endpoint
    if cherrypy.request.path_info == "/auth/login":
        return

    # Get auth handlers from config
    jwt_handler = cherrypy.config.get("jwt_handler")
    token_manager = cherrypy.config.get("token_manager")

    if not jwt_handler or not token_manager:
        logger.error("Auth handlers not initialized in cherrypy.config")
        raise cherrypy.HTTPError(500, "Authentication system not configured")

    # Check for JWT token in Authorization header first
    auth_header = cherrypy.request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header[7:]  # Remove "Bearer " prefix
        payload = jwt_handler.verify_jwt(token)

        if payload:
            cherrypy.request.user = {
                "username": payload.get("sub"),
                "client_id": payload.get("client_id"),
                "auth_type": "jwt",
            }
            return

    # Browser EventSource clients cannot set Authorization headers. Prefer a
    # one-time endpoint-bound ticket in their URLs.
    query_ticket = cherrypy.request.params.get("ticket")
    ticket_manager = cherrypy.config.get("stream_ticket_manager")
    if query_ticket and ticket_manager:
        identity = ticket_manager.consume(query_ticket, cherrypy.request.path_info)
        if identity:
            cherrypy.request.user = {**identity, "auth_type": "stream_ticket"}
            del cherrypy.request.params["ticket"]
            return

    # Check for API token in X-API-Key header
    api_key = cherrypy.request.headers.get("X-API-Key", "")
    if api_key:
        token_info = token_manager.verify_token(api_key)

        if token_info:
            cherrypy.request.user = {
                "token_id": token_info["id"],
                "token_name": token_info["name"],
                "auth_type": "api_token",
            }
            return

    # No valid authentication found
    logger.warning(f"Unauthorized access attempt to {cherrypy.request.path_info}")
    raise cherrypy.HTTPError(401, "Unauthorized - Valid JWT or API token required")


def check_optional_auth():
    """Populate request.user when credentials are supplied, but allow anonymous requests.

    First-run endpoints such as config import need to accept anonymous requests while
    setup is incomplete.  They still need valid supplied credentials to be processed
    so authenticated administrators are not mistaken for anonymous callers after setup.
    """
    if cherrypy.request.method == "OPTIONS":
        return

    params = getattr(cherrypy.request, "params", {}) or {}
    credentials_supplied = bool(
        cherrypy.request.headers.get("Authorization")
        or cherrypy.request.headers.get("X-API-Key")
        or params.get("ticket")
        or params.get("token")
    )
    if not credentials_supplied:
        return

    check_auth()


def register_require_auth_tool():
    if not hasattr(cherrypy.tools, "require_auth"):
        cherrypy.tools.require_auth = cherrypy.Tool("before_handler", check_auth)
        logger.info("CherryPy require_auth tool registered")
    if not hasattr(cherrypy.tools, "optional_auth"):
        cherrypy.tools.optional_auth = cherrypy.Tool("before_handler", check_optional_auth)
        logger.info("CherryPy optional_auth tool registered")
