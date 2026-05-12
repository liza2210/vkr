import mimetypes


def guess_mime_type(path: str) -> str | None:
    mime_type, _ = mimetypes.guess_type(path)
    return mime_type
