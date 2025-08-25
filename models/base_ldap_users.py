# -*- coding: utf-8 -*-
import ldap
from odoo import models, fields, api, SUPERUSER_ID, _
import logging

_logger = logging.getLogger(__name__)



class LDAPUsers(models.AbstractModel):
    """Mixin to add LDAP authentication to res.users
    Modules that need LDAP auth should make res.users inherit this"""

    _name = 'base_act.ldap.users'
    _description = 'Users LDAP Authentication Mixin'
    _inherit = 'base_act.ldap.connector'

    ldap_uid = fields.Char('LDAP UID', readonly=True)
    is_ldap_user = fields.Boolean('LDAP User', default=False)
    badge_number = fields.Char('Badge Number')  # For storing badge from mail field



    @classmethod


    def _sync_ldap_user(self, ldap_attrs, login):
        """Sync user data from LDAP attributes"""

        _logger.info("##############################")
        _logger.info("_sync_ldap_user")
        _logger.info("##############################")


        # Helper to extract attributes
        def get_attr(attrs, key, default=''):
            val = attrs.get(key, [b''])[0]
            return val.decode('utf-8') if isinstance(val, bytes) else val

        # Extract user data
        display_name = get_attr(ldap_attrs, 'displayName')
        badge_number = get_attr(ldap_attrs, 'mail')  # Badge in mail field
        email = get_attr(ldap_attrs, 'userPrincipalName')
        member_of = ldap_attrs.get('memberOf', [])

        # Find or create user
        Users = self.env['res.users']
        user = Users.search([('login', '=', login)], limit=1)

        user_vals = {
            'name': display_name or login,
            'login': login,
            'email': email,
            'ldap_uid': login,
            'is_ldap_user': True,
            'badge_number': badge_number,
        }

        if not user:
            # Create new user
            user_vals['groups_id'] = [(6, 0, [self.env.ref('base.group_user').id])]
            user = Users.create(user_vals)
            _logger.info(f"Created new LDAP user: {login}")
        else:
            # Update existing user
            user.write(user_vals)
            _logger.debug(f"Updated LDAP user: {login}")

        # Sync groups
        self._sync_user_groups(user, member_of)

        return user.id

    def _sync_user_groups(self, user, member_of_list):

        _logger.info("##############################")
        _logger.info("_login")
        _logger.info("##############################")



        """Sync user groups from LDAP"""
        # Get odoo groups from LDAP
        connector = self.env['base_act.ldap.connector']
        odoo_group_names = connector.get_odoo_groups_from_ldap(member_of_list)

        # Get or create group category for LDAP groups
        category = self.env['ir.module.category'].search(
            [('name', '=', 'LDAP Groups')], limit=1
        )
        if not category:
            category = self.env['ir.module.category'].create({
                'name': 'LDAP Groups',
                'description': 'Groups synchronized from LDAP'
            })

        # Remove user from all LDAP-managed groups
        ldap_groups = self.env['res.groups'].search([
            ('name', '=like', 'odoo_%'),
            ('category_id', '=', category.id)
        ])
        user.groups_id = [(3, g.id) for g in ldap_groups]

        # Add user to current LDAP groups
        for group_name in odoo_group_names:
            group = self.env['res.groups'].search([
                ('name', '=', group_name)
            ], limit=1)

            if not group:
                # Parse group name for module and rights
                # Format: odoo_[module]_[rights]
                parts = group_name.split('_')
                if len(parts) >= 3:
                    module_name = parts[1]
                    rights = '_'.join(parts[2:])

                    group = self.env['res.groups'].create({
                        'name': group_name,
                        'category_id': category.id,
                        'comment': f'LDAP Group: {module_name} - {rights}'
                    })
                    _logger.info(f"Created LDAP group: {group_name}")

            user.groups_id = [(4, group.id)]
    #
    # @api.model
    # def cron_sync_ldap_users(self):
    #     """CRON job to sync all LDAP users"""
    #     ICP = self.env['ir.config_parameter'].sudo()
    #     if ICP.get_param('base_act.ldap_enabled', 'False') != 'True':
    #         return
    #
    #     connector = self.env['base_act.ldap.connector']
    #     config = connector.get_ldap_config()
    #
    #     try:
    #         with connector.ldap_connection() as conn:
    #             # Search all users with odoo_ groups
    #             search_filter = "(&(objectClass=user)(memberOf=*odoo_*))"
    #
    #             results = conn.search_s(
    #                 config['base_dn'],
    #                 ldap.SCOPE_SUBTREE,
    #                 search_filter,
    #                 ['sAMAccountName', 'displayName', 'mail', 'memberOf', 'userPrincipalName']
    #             )
    #
    #             for dn, attrs in results:
    #                 if attrs:
    #                     login = attrs.get('sAMAccountName', [b''])[0]
    #                     if login:
    #                         login = login.decode('utf-8') if isinstance(login, bytes) else login
    #                         self._sync_ldap_user(attrs, login)
    #                         _logger.debug(f"Synced LDAP user: {login}")
    #
    #             self.env.cr.commit()
    #             _logger.info(f"LDAP sync completed: {len(results)} users processed")
    #
    #     except Exception as e:
    #         _logger.error(f"CRON LDAP sync error: {str(e)}")