# -*- coding: utf-8 -*-
#
# Copyright (C) 2022 TU Wien.
#
# Invenio-Users-Resources is free software; you can redistribute it and/or
# modify it under the terms of the MIT License; see LICENSE file for more
# details.

"""Definitions that are used by both users and user groups services."""

from invenio_records_resources.services import Link as LinkBase


class Link(LinkBase):
    """Shortcut for writing links with IDs."""

    @staticmethod
    def _sanitize(value, strip_leading_slash=False):
        if value is None or value in ("None", ""):
            return None
        if isinstance(value, str):
            cleaned = value.strip()
            if strip_leading_slash:
                cleaned = cleaned.lstrip("/")
            return cleaned or None
        return value

    @classmethod
    def _value(cls, obj, attr, strip_leading_slash=False):
        """Best-effort extraction of an attribute from record-like objects."""
        value = getattr(obj, attr, None)
        if value not in (None, "None", ""):
            return cls._sanitize(value, strip_leading_slash)

        model = getattr(obj, "model", None)
        if model is not None:
            # Try attribute access on the backing model (AggregateMetadata).
            value = getattr(model, attr, None)
            if value not in (None, "None", ""):
                return cls._sanitize(value, strip_leading_slash)
            data = getattr(model, "_data", None)
            if isinstance(data, dict):
                value = data.get(attr)
                if value not in (None, "None", ""):
                    return cls._sanitize(value, strip_leading_slash)

        if hasattr(obj, "get"):
            value = obj.get(attr)
            if value not in (None, "None", ""):
                return cls._sanitize(value, strip_leading_slash)
        return None

    @classmethod
    def vars(cls, obj, vars):
        """Variables for the URI template."""
        vars.update(
            {
                "id": cls._value(obj, "id", strip_leading_slash=True),
                "username": cls._value(obj, "username"),
            }
        )
