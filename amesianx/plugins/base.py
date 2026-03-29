"""Base class for body transformation plugins."""


class BodyTransformPlugin:
    """Base class for body transformation plugins.

    Subclasses implement detection and transformation for both directions:
      - Inbound (client -> Burp): decode wire format to editable format
      - Outbound (Burp -> target): re-encode editable format to wire format

    transform_* methods return (new_body_bytes, extra_headers_dict).
    """

    name = "BasePlugin"

    def should_transform_inbound(self, body, headers):
        """Return True if this plugin should handle inbound transformation."""
        return False

    def transform_inbound(self, body, headers):
        """Transform body for inbound direction (wire -> editable).
        Returns (new_body_bytes, extra_headers_dict).
        """
        return body, {}

    def should_transform_outbound(self, body, headers):
        """Return True if this plugin should handle outbound transformation."""
        return False

    def transform_outbound(self, body, headers):
        """Transform body for outbound direction (editable -> wire).
        Returns (new_body_bytes, extra_headers_dict).
        """
        return body, {}

    def should_transform_response(self, body, headers):
        """Return True if this plugin should handle response transformation."""
        return False

    def transform_response_decode(self, body, headers):
        """Transform response body: wire -> editable (for viewing in Burp).
        Returns (new_body_bytes, extra_headers_dict).
        """
        return body, {}

    def transform_response_encode(self, body, headers):
        """Transform response body: editable -> wire (restore before sending to client).
        Returns (new_body_bytes, extra_headers_dict).
        """
        return body, {}
