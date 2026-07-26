import logging
import time
from typing import Any

import jwt

logger = logging.getLogger(__name__)


class JWTHandler:
    def __init__(self, secret: str, expiry_minutes: int = 15, security_epoch: int = 0):
        self.secret = secret
        self.expiry_minutes = expiry_minutes
        self.security_epoch = max(0, int(security_epoch))

    def set_security_epoch(self, security_epoch: int) -> None:
        """Invalidate tokens issued under an older authentication boundary."""
        self.security_epoch = max(0, int(security_epoch))

    def create_jwt(
        self,
        username: str,
        client_id: str,
        extra_claims: dict[str, Any] | None = None,
        max_exp: int | None = None,
    ) -> str:

        now = int(time.time())
        expiry = now + (self.expiry_minutes * 60)
        if max_exp is not None:
            expiry = min(expiry, int(max_exp))

        payload = {
            "sub": username,
            "exp": expiry,
            "iat": now,
            "client_id": client_id,
            "security_epoch": self.security_epoch,
        }
        if extra_claims:
            reserved = {"sub", "exp", "iat", "client_id", "security_epoch"}
            overlap = reserved.intersection(extra_claims)
            if overlap:
                raise ValueError(
                    f"JWT extra_claims include reserved claims: {', '.join(sorted(overlap))}"
                )
            payload.update(extra_claims)

        token = jwt.encode(payload, self.secret, algorithm="HS256")
        logger.info(f"Created JWT for user '{username}' with client_id '{client_id[:8]}...'")
        return token

    def verify_jwt(self, token: str) -> dict | None:
        try:
            payload = jwt.decode(token, self.secret, algorithms=["HS256"])
            token_epoch = payload.get("security_epoch", 0)
            if not isinstance(token_epoch, int) or token_epoch != self.security_epoch:
                logger.warning("JWT token was issued before the current security boundary")
                return None
            return payload
        except jwt.ExpiredSignatureError:
            logger.warning("JWT token expired")
            return None
        except jwt.InvalidTokenError as e:
            logger.warning(f"Invalid JWT token: {e}")
            return None
