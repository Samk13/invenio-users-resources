# -*- coding: utf-8 -*-
#
# Copyright (C) 2022 TU Wien.
# Copyright (C) 2024 KTH Royal Institute of Technology.
# Copyright (C) 2024 Ubiquity Press.
# Copyright (C) 2025 KTH Royal Institute of Technology.
#
# Invenio-Users-Resources is free software; you can redistribute it and/or
# modify it under the terms of the MIT License; see LICENSE file for more
# details.

"""Users and user groups permissions."""

from invenio_access import authenticated_user, superuser_access
from invenio_records_permissions import BasePermissionPolicy
from invenio_records_permissions.generators import (
    AdminAction,
    AuthenticatedUser,
    SystemProcess,
)

from invenio_users_resources.permissions import (
    AdministratorGroupAction,
    AdministratorUserAction,
    user_management_action,
)

from .generators import (
    GroupsEnabled,
    IfGroupActionRoleMatches,
    IfGroupNotManaged,
    IfPublicEmail,
    IfPublicUser,
    IfSuperUser,
    IfUserActionRoleMatches,
    PreventSelf,
    Self,
)

UserManager = AdminAction(user_management_action)
UserManagerForGroups = AdministratorGroupAction(user_management_action)
UserManagerForUsers = AdministratorUserAction(user_management_action)
SuperAdminManager = AdminAction(superuser_access)


class UsersPermissionPolicy(BasePermissionPolicy):
    """Permission policy for users and user groups."""

    can_create = [UserManager, SystemProcess()]
    can_read = [
        UserManager,
        IfPublicUser(then_=[AuthenticatedUser()], else_=[Self()]),
        SystemProcess(),
    ]
    can_search = [AuthenticatedUser(), SystemProcess()]
    can_update = [SystemProcess()]
    can_delete = [SystemProcess()]

    can_read_email = [
        UserManager,
        IfPublicEmail([AuthenticatedUser()], [Self()]),
        SystemProcess(),
    ]
    can_read_details = [UserManager, Self(), SystemProcess()]
    can_read_all = [
        SystemProcess(),
        IfUserActionRoleMatches(
            [SuperAdminManager, UserManagerForUsers], [SystemProcess()]
        ),
    ]

    # Moderation permissions
    can_manage = [UserManager, PreventSelf(), SystemProcess()]
    can_search_all = [UserManager, SystemProcess()]
    can_read_system_details = [UserManager, SystemProcess()]
    can_impersonate = [
        SystemProcess(),
        IfUserActionRoleMatches(
            [SuperAdminManager, PreventSelf(), UserManagerForUsers], [SystemProcess()]
        ),
    ]
    can_manage_groups = [
        SystemProcess(),
        IfGroupActionRoleMatches(
            [SuperAdminManager, UserManagerForGroups], [SystemProcess()]
        ),
    ]


class GroupsPermissionPolicy(BasePermissionPolicy):
    """Permission policy for users and user groups."""

    _can_any = [
        GroupsEnabled("group"),
        SystemProcess(),
        UserManager,
    ]
    can_create = _can_any + [
        IfGroupNotManaged([AuthenticatedUser()], [UserManagerForGroups]),
    ]
    can_read = _can_any + [
        IfSuperUser(
            [SuperAdminManager],
            [
                IfGroupNotManaged(
                    [AuthenticatedUser()],
                    [AdministratorGroupAction(authenticated_user)],
                )
            ],
        ),
    ]
    can_search = _can_any + [AuthenticatedUser()]
    can_update = _can_any + [
        IfGroupActionRoleMatches(
            [SuperAdminManager, UserManagerForGroups], [SystemProcess()]
        ),
    ]
    can_manage = _can_any + [
        IfGroupActionRoleMatches(
            [SuperAdminManager, UserManagerForGroups], [SystemProcess()]
        ),
    ]
    can_delete = _can_any + [
        IfGroupActionRoleMatches(
            [SuperAdminManager, UserManagerForGroups], [SystemProcess()]
        )
    ]


class DomainPermissionPolicy(BasePermissionPolicy):
    """Permission policy for users and user groups."""

    can_create = [UserManager, SystemProcess()]
    can_read = [UserManager, SystemProcess()]
    can_search = [UserManager, SystemProcess()]
    can_update = [UserManager, SystemProcess()]
    can_delete = [UserManager, SystemProcess()]
