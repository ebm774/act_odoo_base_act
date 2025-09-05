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
    worker_id = fields.Integer('Worker Number')
    email = fields.Char('Email')

    def _sync_ldap_user(self, ldap_attrs, login):
        """Sync user data from LDAP attributes"""
        _logger.info("##############################")
        _logger.info("_sync_ldap_user")
        _logger.info("##############################")

        # Add debug logging to see what we're getting
        _logger.info(f"[DEBUG] ldap_attrs type: {type(ldap_attrs)}")
        _logger.info(f"[DEBUG] ldap_attrs content: {ldap_attrs}")

        #  Early validation - fail fast if not a dict
        if not isinstance(ldap_attrs, dict):
            _logger.error(f"[LDAP] Expected dict for ldap_attrs, got {type(ldap_attrs)}: {ldap_attrs}")
            return None

        # Helper to extract attributes
        def get_attr(attrs, key, default=''):
            # ✅ Fixed: Only proceed if attrs is a dict
            if not isinstance(attrs, dict):
                return default
            val = attrs.get(key, [b''])[0] if attrs.get(key) else b''
            return val.decode('utf-8') if isinstance(val, bytes) else default

        # Extract user data
        display_name = get_attr(ldap_attrs, 'displayName')
        badge_number = get_attr(ldap_attrs, 'employeeID')
        worker_id = get_attr(ldap_attrs, 'employeeNumber')
        email = get_attr(ldap_attrs, 'userPrincipalName')
        ldap_login = get_attr(ldap_attrs, 'sAMAccountName')
        member_of = ldap_attrs.get('memberOf', []) if isinstance(ldap_attrs, dict) else []

        # Use the login from LDAP if available, otherwise use the passed login
        if not ldap_login:
            ldap_login = login


        # Find existing user
        user = None
        worker_id_int = int(worker_id) if worker_id and worker_id.isdigit() else 0
        if worker_id_int:
            user = self.search([('worker_id', '=', worker_id_int)], limit=1)
        if not user:
            user = self.search([('login', '=', ldap_login)], limit=1)

        # Get the default company
        company = self.env.company or self.env['res.company'].sudo().search([], limit=1)

        user_vals = {
            'name': display_name or ldap_login,
            'login': ldap_login,
            'email': email,
            'ldap_uid': ldap_login,
            'is_ldap_user': True,
            'badge_number': badge_number or '',
            'worker_id': int(worker_id) if worker_id and worker_id.isdigit() else 0,
            'company_id': company.id,
            'company_ids': [(4, company.id)],
        }

        _logger.info(f"User values prepared for {ldap_login}")

        if not user:
            _logger.info(f"Creating new user for {ldap_login}")
            # Add default group for new users
            user_vals['groups_id'] = [(6, 0, [self.env.ref('base.group_user').id])]

            try:
                # Create using the res.users model, not self
                # user = self.sudo().create(user_vals)

                user = self.sudo().with_context(no_reset_password=True).create(user_vals)
                _logger.info(f"Created new LDAP user: {ldap_login} with ID: {user.id}")
                self._sync_user_groups(user, member_of)
                return user.id
            except Exception as e:
                _logger.error(f"Failed to create user {ldap_login}: {e}")
                return False
        else:
            _logger.info(f"Updating existing user {ldap_login}")
            try:


                user_with_context = user.sudo().with_context(
                    mail_notrack=True,
                    tracking_disable=True,
                    no_login_notification=True,
                    skip_password_notification=True
                )


                user_with_context.write(user_vals)
                _logger.info(f"Updated LDAP user: {login}")


                self._sync_user_groups(user_with_context, member_of)

                return user.id
            except Exception as e:
                _logger.error(f"Failed to update user {ldap_login}: {e}")
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

    @api.model
    def cron_sync_ldap_users_with_employee_id(self):
        """CRON job to sync LDAP users with employeeId using existing auth process"""
        _logger.info("Starting LDAP user sync for users with employeeId")

        ICP = self.env['ir.config_parameter'].sudo()
        if ICP.get_param('base_act.ldap_enabled', 'False') != 'True':
            _logger.info("LDAP not enabled, skipping sync")
            return

        connector = self.env['base_act.ldap.connector']
        config = connector.get_ldap_config()
        users_synced = 0
        users_created = 0
        users_updated = 0
        disabled_ou_filtered = 0
        disabled_ou = 0

        try:
            with connector.ldap_connection() as conn:
                # Use a broader search to get all users, then filter, exclud disabled OU
                search_filter = "(&(objectClass=user)(sAMAccountName=*))"

                results = conn.search_s(
                    config['base_dn'],
                    ldap.SCOPE_SUBTREE,
                    search_filter,
                    ['sAMAccountName', 'displayName', 'mail', 'memberOf',
                     'userPrincipalName', 'employeeID', 'employeeNumber', 'distinguishedName']
                )


                # Use the same referral filtering logic as search_user method
                for entry in results:
                    # Skip invalid entries and referrals (same as your working search_user method)
                    if not isinstance(entry, tuple) or len(entry) != 2:
                        continue

                    dn, attrs = entry

                    # Skip LDAP referrals and invalid entries
                    if not attrs or not isinstance(attrs, dict) or 'sAMAccountName' not in attrs:
                        continue

                    distinguished_name = attrs.get('distinguishedName', [])
                    if distinguished_name:
                        dn_str = distinguished_name[0]
                        dn_str = dn_str.decode('utf-8') if isinstance(dn_str, bytes) else dn_str
                        dn_str = dn_str.upper()
                        if ('OU=DISABLED_AFTER_SEPTEMBER_2025' in dn_str or
                                'OU=DISABLED_BEFORE_SEPTEMBER_2025' in dn_str):
                            disabled_ou_filtered += 1
                            _logger.debug(f"Filtered out disabled OU user: {dn_str}")
                            continue

                    login_raw = attrs.get('sAMAccountName', [])
                    employee_id_raw = attrs.get('employeeID', [])

                    if not login_raw:
                        continue

                    login = login_raw[0]
                    login = login.decode('utf-8') if isinstance(login, bytes) else login

                    # Check if employeeId exists and is not "<not set>"
                    if not employee_id_raw:
                        continue

                    employee_id = employee_id_raw[0]
                    employee_id = employee_id.decode('utf-8') if isinstance(employee_id, bytes) else employee_id

                    # Skip if employeeId is "<not set>" or similar
                    if employee_id.strip().lower() in ['<not set>', 'not set', '', 'null']:
                        continue

                    try:
                        # Extract employeeNumber for matching
                        employee_number_raw = attrs.get('employeeNumber', [])
                        employee_number = None
                        if employee_number_raw:
                            employee_number = employee_number_raw[0]
                            employee_number = employee_number.decode('utf-8') if isinstance(employee_number,
                                                                                            bytes) else employee_number
                            employee_number = int(
                                employee_number) if employee_number and employee_number.isdigit() else None

                        distinguished_name = attrs.get('distinguishedName', [])
                        if distinguished_name:
                            dn_str = distinguished_name[0]
                            dn_str = dn_str.decode('utf-8') if isinstance(dn_str, bytes) else dn_str
                            dn_str = dn_str.upper()  # Convert to uppercase for case-insensitive matching
                            if ('OU=DISABLED_AFTER_SEPTEMBER_2025' in dn_str or
                                    'OU=DISABLED_BEFORE_SEPTEMBER_2025' in dn_str):
                                disabled_ou_filtered += 1  # ✅ Use the declared variable
                                _logger.debug(f"Filtered out disabled OU user: {dn_str}")
                                continue
                                # Convert to uppercase for case-insensitive matching
                            if ('OU=DISABLED_AFTER_SEPTEMBER_2025' in dn_str or
                                    'OU=DISABLED_BEFORE_SEPTEMBER_2025' in dn_str):
                                disabled_ou += 1
                                _logger.debug(f"Filtered out disabled OU user: {dn}")
                                continue

                        existing_user = None
                        if employee_number:
                            existing_user = self.search([('worker_id', '=', employee_number)], limit=1)

                        # If not found by worker_id, try by login as fallback
                        if not existing_user:
                            existing_user = self.search([('login', '=', login)], limit=1)

                        if existing_user:
                            # Update existing user using existing sync method
                            existing_user.sudo().with_context(
                                no_reset_password=True,
                                mail_create_nosubscribe=True,
                                mail_create_nolog=True
                            )._sync_ldap_user(attrs, login)
                            users_updated += 1
                            _logger.debug(f"Updated LDAP user: {login} (worker_id: {employee_number})")
                        else:
                            # Create new user using existing sync method (same as auth flow)
                            result = self.sudo().with_context(
                                no_reset_password=True,
                                mail_create_nosubscribe=True,
                                mail_create_nolog=True
                            )._sync_ldap_user(attrs, login)
                            if result:
                                users_created += 1
                                _logger.debug(f"Created LDAP user: {login} (worker_id: {employee_number})")

                        users_synced += 1

                    except Exception as user_error:
                        _logger.error(f"Failed to sync user {login}: {str(user_error)}")
                        continue

                self.env.cr.commit()
                _logger.info(
                    f"LDAP sync completed: {users_synced} total, {users_created} created, {users_updated} updated")

        except Exception as e:
            _logger.error(f"CRON LDAP sync error: {str(e)}")
            self.env.cr.rollback()

    def _create_ldap_user_from_cron(self, ldap_attrs, login):
        """Create LDAP user from cron job without requiring password authentication"""
        _logger.info(f"Creating LDAP user from cron: {login}")

        # Early validation - fail fast if not a dict
        if not isinstance(ldap_attrs, dict):
            _logger.error(f"[LDAP] Expected dict for ldap_attrs, got {type(ldap_attrs)}: {ldap_attrs}")
            return None

        # Helper to extract attributes (same as in _sync_ldap_user)
        def get_attr(attrs, key, default=''):
            if not isinstance(attrs, dict):
                return default
            val = attrs.get(key, [b''])[0] if attrs.get(key) else b''
            return val.decode('utf-8') if isinstance(val, bytes) else default

        # Extract user data
        display_name = get_attr(ldap_attrs, 'displayName')
        badge_number = get_attr(ldap_attrs, 'employeeID')  # ✅ Use consistent employeeID
        worker_id = get_attr(ldap_attrs, 'employeeNumber')
        email = get_attr(ldap_attrs, 'userPrincipalName')
        ldap_login = get_attr(ldap_attrs, 'sAMAccountName')
        member_of = ldap_attrs.get('memberOf', [])


        try:
            worker_id_int = int(worker_id) if worker_id and worker_id.isdigit() else 0
        except (ValueError, AttributeError):
            worker_id_int = 0

        # Create user directly
        user_vals = {
            'name': display_name or login,
            'login': login,
            'email': email,
            'ldap_uid': login,
            'is_ldap_user': True,
            'badge_number': badge_number or '',
            'worker_id': worker_id_int,
            'active': True,
            'password': None,  # LDAP users don't have local passwords
        }

        try:
            user = self.sudo().with_context(
                mail_create_nolog=True,  # Don't log creation
                mail_create_nosubscribe=True,  # Don't auto-subscribe
                tracking_disable=True  # Disable all tracking
            ).create(user_vals)
            _logger.info(f"Created new LDAP user: {login} (ID: {user.id})")

            # Sync LDAP groups to Odoo groups
            self._sync_user_groups(user, member_of)

            return user.id
        except Exception as e:
            _logger.error(f"Failed to create LDAP user {login}: {str(e)}")
            return None