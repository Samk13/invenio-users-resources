# -*- coding: utf-8 -*-
#
# Copyright (C) 2023 CERN.
#
# Invenio-Users-Resources is free software; you can redistribute it and/or modify
# it under the terms of the MIT License; see LICENSE file for more details.
"""Users resources generic needs and permissions."""

from invenio_access import ActionRoles, Permission, action_factory, superuser_access
from invenio_records_permissions.generators import AdminAction
from invenio_search.engine import dsl

USER_MANAGEMENT_ACTION_NAME = "administration-moderation"

user_management_action = action_factory(USER_MANAGEMENT_ACTION_NAME)


class SuperUserMixin:
    """Mixin for superuser permissions."""

    def _get_superadmin_roles(self):
        """Get all roles with superuser access action role."""
        return ActionRoles.query_by_action(superuser_access).all()

    def _get_superadmin_users(self):
        return {
            user.id for role in self._get_superadmin_roles() for user in role.role.users
        }

    def _get_superadmin_groups(self):
        return {role.role.name for role in self._get_superadmin_roles()}

    def _is_group_superadmin(self, group_id, roles):
        """Check if the group has the superuser role."""
        groups = {role.role.id for role in roles}
        if group_id in groups:
            return True
        return False

    def _is_user_superadmin(self, identity, roles=None):
        """Check if the user has the superuser role."""
        roles = roles if roles else self._get_superadmin_roles()
        users = {user.id for role in roles for user in role.role.users}
        if identity.id in users:
            return True
        return False

    def check_permission(self, identity, action_name, **kwargs):
        """Check a permission against the identity."""
        kwargs["identity"] = identity
        return self.permission_policy(action_name, **kwargs).allows(identity)


class AdministratorGroupAction(SuperUserMixin, AdminAction):
    """Generator for user administrator needs.
    This generator's purpose is to be used in cases where administration needs are required.
    The query filter of this generator is quite broad (match_all). Therefore, it must be used with care.
    """

    def query_filter(self, identity, **kwargs):
        """If the user is user moderator then can query all but super user groups."""
        permission = Permission(self.action)
        if permission.allows(identity):
            role_names = self._get_superadmin_groups()
            return dsl.Q("match_all") & ~dsl.Q("terms", **{"name": list(role_names)})
        return []


class AdministratorUserAction(SuperUserMixin, AdminAction):
    """Generator for user administrator needs.
    This generator's purpose is to be used in cases where administration needs are required.
    The query filter of this generator is quite broad (match_all). Therefore, it must be used with care.
    """

    def query_filter(self, identity, **kwargs):
        """If the user is user moderator then can query all but super user groups."""
        permission = Permission(self.action)
        if permission.allows(identity):
            user_names = self._get_superadmin_users()
            return dsl.Q("match_all") & ~dsl.Q("terms", **{"id": list(user_names)})
        return []
