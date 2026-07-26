import logging
from functools import wraps

import cherrypy

logger = logging.getLogger(__name__)


def require_auth(func):

    @wraps(func)
    def wrapper(*args, **kwargs):
        # Terminate CORS preflight without invoking the protected handler.
        if cherrypy.request.method == "OPTIONS":
            cherrypy.response.status = 204
            return b""

        # Get auth handlers from global cherrypy config (not app config)
        jwt_handler = cherrypy.config.get("jwt_handler")
        token_manager = cherrypy.config.get("token_manager")

        if not jwt_handler or not token_manager:
            logger.error("Auth handlers not configured")
            raise cherrypy.HTTPError(500, "Authentication not configured")

        # Try JWT authentication first
        auth_header = cherrypy.request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header[7:]  # Remove 'Bearer ' prefix
            payload = jwt_handler.verify_jwt(token)

            if payload:
                # JWT is valid
                cherrypy.request.user = {
                    "username": payload["sub"],
                    "client_id": payload["client_id"],
                    "auth_type": "jwt",
                }
                return func(*args, **kwargs)
            else:
                logger.warning("Invalid or expired JWT token")

        request_params = getattr(cherrypy.request, "params", None)
        if request_params is None:
            request_params = {}

        query_ticket = request_params.get("ticket")
        ticket_manager = cherrypy.config.get("stream_ticket_manager")
        if query_ticket and ticket_manager:
            identity = ticket_manager.consume(query_ticket, cherrypy.request.path_info)
            if identity:
                cherrypy.request.user = {**identity, "auth_type": "stream_ticket"}
                if hasattr(cherrypy.request, "params"):
                    cherrypy.request.params.pop("ticket", None)
                return func(*args, **kwargs)

        # Try API token authentication
        api_key = cherrypy.request.headers.get("X-API-Key", "")
        if api_key:
            token_info = token_manager.verify_token(api_key)

            if token_info:
                # API token is valid
                cherrypy.request.user = {
                    "username": "api_token",
                    "token_name": token_info["name"],
                    "token_id": token_info["id"],
                    "auth_type": "api_token",
                }
                return func(*args, **kwargs)
            else:
                logger.warning("Invalid API token")

        # No valid authentication found
        logger.warning(f"Unauthorized access attempt to {cherrypy.request.path_info}")

        cherrypy.response.status = 401
        cherrypy.response.headers["Content-Type"] = "application/json"
        return {"success": False, "error": "Unauthorized - Valid JWT or API token required"}

    return wrapper
