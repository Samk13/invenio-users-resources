# -*- coding: utf-8 -*-
#
# Copyright (C) 2022-2024 KTH Royal Institute of Technology.
# Copyright (C) 2022 TU Wien.
# Copyright (C) 2022 European Union.
# Copyright (C) 2022 CERN.
# Copyright (C) 2024 Ubiquity Press.
#
# Invenio-Users-Resources is free software; you can redistribute it and/or
# modify it under the terms of the MIT License; see LICENSE file for more
# details.

"""Users service."""

import secrets
import string

from flask import current_app
from flask_security.utils import hash_password
from invenio_accounts.models import User
from invenio_accounts.proxies import current_datastore
from invenio_accounts.utils import default_reset_password_link_func
from invenio_db import db
from invenio_i18n import lazy_gettext as _
from invenio_records_resources.resources.errors import PermissionDeniedError
from invenio_records_resources.services import RecordService
from invenio_records_resources.services.uow import RecordCommitOp, TaskOp, unit_of_work
from invenio_search import current_search_client
from invenio_search.engine import dsl
from marshmallow import ValidationError

from invenio_users_resources.permissions import SuperUserMixin
from invenio_users_resources.proxies import current_groups_service
from invenio_users_resources.services.results import AvatarResult
from invenio_users_resources.services.users.tasks import (
    execute_moderation_actions,
    execute_reset_password_email,
)

from ...records.api import GroupAggregate, UserAggregate
from .lock import ModerationMutex


class UsersService(SuperUserMixin, RecordService):
    """Users service."""

    def __init__(self, config, *args, **kwargs):
        """Constructor."""
        super().__init__(config, *args, **kwargs)
        self._username_sort_configured = False
        self._username_sort_field = None

    @property
    def user_cls(self):
        """Alias for record_cls."""
        return self.record_cls

    @unit_of_work()
    def create(self, identity, data, raise_errors=True, uow=None):
        """Create a user from users admin."""
        self.require_permission(identity, "create")
        # Remove None values to avoid validation issues
        data = {k: v for k, v in data.items() if v is not None}
        # validate new user data
        data, errors = self.schema.load(
            data,
            context={"identity": identity},
            raise_errors=raise_errors,
        )
        # create user
        user = self._create_user(data)
        # run components
        self.run_components(
            "create",
            identity,
            data=data,
            user=user,
            errors=errors,
            uow=uow,
        )
        uow.register(RecordCommitOp(user, indexer=self.indexer, index_refresh=True))
        # get email token and reset info
        account_user = current_datastore.get_user(user.id)
        token, reset_link = default_reset_password_link_func(account_user)
        # trigger celery task to send email after the user was successfully created
        uow.register(
            TaskOp(
                execute_reset_password_email,
                user_id=user.id,
                token=token,
                reset_link=reset_link,
            )
        )
        return self.result_item(
            self, identity, user, links_tpl=self.links_item_tpl, errors=errors
        )

    def _generate_password(self, length=12):
        """Generate password of a specific length."""
        alphabet = string.ascii_letters + string.digits
        return "".join(secrets.choice(alphabet) for _ in range(length))

    def _create_user(self, user_info: dict):
        """Create a new active and verified user with auto-generated password."""
        # Generate password and add to user_info dict
        user_info["password"] = hash_password(self._generate_password())

        # Create the user with the specified data
        user = self.user_cls.create(user_info)
        # Activate and verify user
        user.activate()
        user.verify()
        return user

    def search(self, identity, params=None, search_preference=None, **kwargs):
        """Search for active and confirmed users, matching the query."""
        self._ensure_username_sort_field()
        return super().search(
            identity,
            params=params,
            search_preference=search_preference,
            extra_filter=dsl.Q("term", active=True) & dsl.Q("term", confirmed=True),
            **kwargs,
        )

    def search_all(
        self,
        identity,
        params=None,
        search_preference=None,
        extra_filters=None,
        **kwargs,
    ):
        """Search for all users, without restrictions."""
        self.require_permission(identity, "search_all")
        self._ensure_username_sort_field()

        params = params or {}
        role_filter, selected_roles = self._extract_roles_filter(identity, params)
        combined_filters = extra_filters
        if role_filter is not None:
            combined_filters = (
                role_filter
                if combined_filters is None
                else role_filter & combined_filters
            )

        result = super().search(
            identity,
            params=params,
            search_preference=search_preference,
            search_opts=self.config.search_all,
            permission_action="read_all",
            extra_filter=combined_filters,
            **kwargs,
        )
        self._restore_roles_facet(params, selected_roles)
        result.roles_aggregation = self._build_roles_aggregation(
            identity, selected_roles
        )
        return result

    def read(self, identity, id_):
        """Retrieve a user."""
        # resolve and require permission
        user = UserAggregate.get_record(id_)
        # TODO - email user issue
        if user is None:
            # return 403 even on empty resource due to security implications
            raise PermissionDeniedError()

        self.require_permission(identity, "read", record=user)

        # run components
        for component in self.components:
            if hasattr(component, "read"):
                component.read(identity, user=user)

        return self.result_item(self, identity, user, links_tpl=self.links_item_tpl)

    def read_avatar(self, identity, id_):
        """Get a user's avatar."""
        user = UserAggregate.get_record(id_)
        if user is None:
            # return 403 even on empty resource due to security implications
            raise PermissionDeniedError()
        self.require_permission(identity, "read", record=user)
        return AvatarResult(user)

    @unit_of_work()
    def update(self, identity, id_, data, raise_errors=True, uow=None):
        """Update a user (requires manage permission - prevents self-editing)."""
        user = UserAggregate.get_record(id_)
        if user is None:
            raise PermissionDeniedError()

        # This will prevent users from editing themselves via PreventSelf
        self._check_permission(identity, "manage", user)

        # Validate and update user data
        data, errors = self.schema.load(
            data,
            context={"identity": identity},
            raise_errors=raise_errors,
        )

        # Update user fields
        user.update(data)

        # Run components
        self.run_components(
            "update",
            identity,
            data=data,
            user=user,
            errors=errors,
            uow=uow,
        )

        uow.register(RecordCommitOp(user, indexer=self.indexer, index_refresh=True))

        return self.result_item(
            self, identity, user, links_tpl=self.links_item_tpl, errors=errors
        )

    def rebuild_index(self, identity, uow=None):
        """Reindex all users managed by this service."""
        users = db.session.query(User.id).yield_per(1000)
        self.indexer.bulk_index([u.id for u in users])
        return True

    def _extract_roles_filter(self, identity, params):
        """Extract role selections and build an OpenSearch filter."""
        facets = params.get("facets") or {}
        selected = list(facets.pop("roles", []) or [])

        if not selected:
            return None, []

        allowed = self._filter_allowed_roles(identity, selected)
        disallowed = set(selected) - set(allowed)
        if disallowed:
            raise PermissionDeniedError("manage_groups")

        user_ids = self._role_user_ids(allowed)
        if not user_ids:
            return dsl.Q("match_none"), selected

        return dsl.Q("terms", uuid=list(user_ids)), selected

    def _restore_roles_facet(self, params, selected_roles):
        """Restore the role facet after search execution."""
        if not selected_roles:
            return
        facets = params.setdefault("facets", {})
        facets["roles"] = selected_roles

    def _filter_allowed_roles(self, identity, role_names):
        """Return the subset of roles the identity may manage."""
        allowed = []
        for role_name in role_names:
            group = GroupAggregate.get_record_by_name(role_name)
            if group is None:
                continue
            if self.check_permission(identity, "manage_groups", record=group):
                allowed.append(role_name)
        return allowed

    def _role_user_ids(self, role_names):
        """Return the set of user IDs for the given role names."""
        if not role_names:
            return set()

        active_map = self._active_user_map(role_names)
        user_ids = set()
        for ids in active_map.values():
            user_ids.update(ids)
        return user_ids

    def _available_roles(self, identity):
        """Roles visible to the identity."""
        role_model = current_datastore.role_model
        roles = db.session.query(role_model).order_by(role_model.name.asc()).all()
        visible = []
        for role in roles:
            group = GroupAggregate.from_model(role)
            try:
                if current_groups_service.check_permission(
                    identity, "read", record=group
                ):
                    visible.append(role)
            except PermissionDeniedError:
                continue
        return visible

    def _build_roles_aggregation(self, identity, selected_roles):
        """Build aggregation payload for the synthetic roles facet."""
        roles = self._available_roles(identity)
        if not roles:
            return None

        role_names = [role.name for role in roles]
        active_map = self._active_user_map(role_names)
        selected = set(selected_roles or [])
        buckets = []
        for role in roles:
            label = self._truncate_label(role.name)
            doc_count = len(active_map.get(role.name, set()))
            if doc_count == 0:
                continue
            buckets.append(
                {
                    "key": role.name,
                    "doc_count": doc_count,
                    "label": label,
                    "is_selected": role.name in selected,
                }
            )
        return {"label": str(_("Roles")), "buckets": buckets}

    def _active_user_map(self, role_names=None):
        """Return a mapping of role name to active user id set."""
        role_model = current_datastore.role_model
        user_model = current_datastore.user_model

        query = (
            db.session.query(role_model.name, user_model.id)
            .join(role_model.users)
            .filter(user_model.active.is_(True))
        )
        if role_names:
            query = query.filter(role_model.name.in_(role_names))

        rows = query.all()
        mapping = {name: set() for name in (role_names or [])}
        for role_name, user_id in rows:
            mapping.setdefault(role_name, set()).add(user_id)
        return mapping

    def _truncate_label(self, label, max_length=25):
        """Ensure facet labels do not overflow the UI."""
        if label and len(label) > max_length:
            return f"{label[: max_length]}…"
        return label

    def _ensure_username_sort_field(self):
        """Ensure the username sort option targets an existing field."""
        if self._username_sort_configured:
            return

        sort_field = self._detect_username_sort_field()
        search_opts = [
            getattr(self.config, "search_all", None),
            getattr(self.config, "search", None),
        ]
        for opts in search_opts:
            if not opts:
                continue
            sort_options = getattr(opts, "sort_options", None)
            if not sort_options:
                continue
            sort_def = sort_options.get("username")
            if not sort_def:
                continue
            fields = sort_def.get("fields") or []
            if fields:
                fields[0] = sort_field
        self._username_sort_configured = True

    def _detect_username_sort_field(self):
        """Determine which field should be used for username sorting."""
        if self._username_sort_field:
            return self._username_sort_field

        try:
            mapping = current_search_client.indices.get_mapping(
                index=self.record_cls.index._name
            )
            username_defs = []
            for entry in mapping.values():
                props = entry.get("mappings", {}).get("properties", {})
                username_def = props.get("username")
                if username_def:
                    username_defs.append(username_def)

            if username_defs:
                if all("keyword" in (ud.get("fields") or {}) for ud in username_defs):
                    self._username_sort_field = "username.keyword"
                elif all((ud or {}).get("type") == "keyword" for ud in username_defs):
                    self._username_sort_field = "username"
        except Exception as exc:
            current_app.logger.debug("Could not inspect username mapping: %s", exc)

        if not self._username_sort_field:
            # Default to keyword field; if it does not exist, OpenSearch
            # will surface the issue instead of sorting on a text field.
            self._username_sort_field = "username.keyword"
            current_app.logger.debug(
                "Using username.keyword for sorting; mapping inspection failed."
            )

        return self._username_sort_field

    def _check_permission(self, identity, permission_type, user):
        """Checks if given identity has the specified permission type on the user."""
        self.require_permission(
            identity, permission_type, record=user, actor_id=identity.id
        )

    @unit_of_work()
    def block(self, identity, id_, uow=None):
        """Blocks a user."""
        user = UserAggregate.get_record(id_)
        if user is None:
            # return 403 even on empty resource due to security implications
            raise PermissionDeniedError()
        self._check_permission(identity, "manage", user)

        if user.blocked:
            raise ValidationError("User is already blocked.")

        # Throws if not acquired
        ModerationMutex(id_).acquire()
        user.block()
        uow.register(RecordCommitOp(user, indexer=self.indexer, index_refresh=True))

        # Register a task to execute callback actions asynchronously, after committing the user
        uow.register(
            TaskOp(execute_moderation_actions, user_id=user.id, action="block")
        )
        return True

    @unit_of_work()
    def restore(self, identity, id_, uow=None):
        """Restores a user."""
        user = UserAggregate.get_record(id_)
        if user is None:
            # return 403 even on empty resource due to security implications
            raise PermissionDeniedError()
        self._check_permission(identity, "manage", user)

        if not user.blocked:
            raise ValidationError("User is not blocked.")

        # Throws if not acquired
        ModerationMutex(id_).acquire()
        user.activate()
        # User is blocked from now on, "after" actions are executed separately.
        uow.register(RecordCommitOp(user, indexer=self.indexer, index_refresh=True))

        # Register a task to execute callback actions asynchronously, after committing the user
        uow.register(
            TaskOp(execute_moderation_actions, user_id=user.id, action="restore")
        )
        return True

    @unit_of_work()
    def approve(self, identity, id_, uow=None):
        """Approves a user."""
        user = UserAggregate.get_record(id_)
        if user is None:
            # return 403 even on empty resource due to security implications
            raise PermissionDeniedError()
        self._check_permission(identity, "manage", user)

        if user.verified:
            raise ValidationError("User is already verified.")

        # Throws if not acquired
        ModerationMutex(id_).acquire()
        user.verify()
        uow.register(RecordCommitOp(user, indexer=self.indexer, index_refresh=True))

        # Register a task to execute callback actions asynchronously, after committing the user
        uow.register(
            TaskOp(execute_moderation_actions, user_id=user.id, action="approve")
        )
        return True

    @unit_of_work()
    def deactivate(self, identity, id_, uow=None):
        """Deactivates a user."""
        user = UserAggregate.get_record(id_)
        if user is None:
            # return 403 even on empty resource due to security implications
            raise PermissionDeniedError()
        self._check_permission(identity, "manage", user)

        if not user.active:
            raise ValidationError("User is already inactive.")

        user.deactivate()
        uow.register(RecordCommitOp(user, indexer=self.indexer, index_refresh=True))
        return True

    @unit_of_work()
    def activate(self, identity, id_, uow=None):
        """Activate a user."""
        user = UserAggregate.get_record(id_)
        if user is None:
            # return 403 even on empty resource due to security implications
            raise PermissionDeniedError()
        self._check_permission(identity, "manage", user)

        if user.active and user.confirmed:
            raise ValidationError("User is already active.")
        user.activate()
        uow.register(RecordCommitOp(user, indexer=self.indexer, index_refresh=True))
        return True

    def can_impersonate(self, identity, id_):
        """Check permissions if a user can be impersonated."""
        user = UserAggregate.get_record(id_)
        if user is None:
            # return 403 even on empty resource due to security implications
            raise PermissionDeniedError()
        self._check_permission(identity, "impersonate", user)

        return user.model.model_obj

    @unit_of_work()
    def add_group(self, identity, id_, group_name, uow=None):
        """Assign a group to the given user."""
        user = UserAggregate.get_record(id_)
        if user is None:
            raise PermissionDeniedError("manage_groups")
        self._check_permission(identity, "manage_groups", user)

        group = GroupAggregate.get_record_by_name(group_name)
        if group is None:
            raise ValidationError("Unknown group.")

        self.require_permission(identity, "manage_groups", record=group)
        added = user.add_group(group_name)
        if not added:
            return False

        # Don't explicitly index - the database hooks will handle reindexing
        # when the User model is modified (see records/hooks.py)
        return True

    @unit_of_work()
    def remove_group(self, identity, id_, group_name, uow=None):
        """Remove a group from the given user."""
        user = UserAggregate.get_record(id_)
        if user is None:
            raise PermissionDeniedError("manage_groups")
        self._check_permission(identity, "manage_groups", user)

        group = GroupAggregate.get_record_by_name(group_name)
        if group is None:
            return False

        self.require_permission(identity, "manage_groups", record=group)
        removed = user.remove_group(group_name)
        if not removed:
            return False

        # Don't explicitly index - the database hooks will handle reindexing
        # when the User model is modified (see records/hooks.py)
        return True

    def list_groups(self, identity, id_):
        """List the groups assigned to a user."""
        user = UserAggregate.get_record(id_)
        if user is None:
            raise PermissionDeniedError()
        self.require_permission(identity, "read", record=user)

        groups = user.get_groups()
        hits = [
            {
                "id": role.id,
                "name": role.name,
                "description": role.description,
                "is_managed": role.is_managed,
            }
            for role in groups
        ]
        return {"hits": {"hits": hits}}
