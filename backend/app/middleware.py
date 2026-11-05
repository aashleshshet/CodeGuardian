from starlette.responses import JSONResponse


class BodyLimitMiddleware:
    """Limit streaming bodies before Starlette's multipart parser can spool them to disk."""
    def __init__(self, app, maximum=10_500_000):
        self.app, self.maximum = app, maximum

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http": return await self.app(scope, receive, send)
        size, started = 0, False
        class TooLarge(Exception): pass
        async def bounded_receive():
            nonlocal size
            message = await receive()
            if message["type"] == "http.request":
                size += len(message.get("body", b""))
                if size > self.maximum: raise TooLarge()
            return message
        async def tracked_send(message):
            nonlocal started
            if message["type"] == "http.response.start": started = True
            await send(message)
        try: await self.app(scope, bounded_receive, tracked_send)
        except TooLarge:
            if not started: await JSONResponse({"detail": "Request body exceeds the upload limit"}, 413)(scope, receive, send)
