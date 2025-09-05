def _is_user_in_odoo_group(self, member_of_list):
    """Check if user is member of the specific 'odoo' group"""
    if not member_of_list:
        return False

    target_group = "CN=odoo,CN=Builtin,DC=autocontrole,DC=be"

    for group_dn in member_of_list:
        group_dn_str = group_dn.decode('utf-8') if isinstance(group_dn, bytes) else group_dn

        # Direct string comparison (case sensitive)
        if group_dn_str == target_group:
            return True

    return False  # -*- coding: utf-8 -*-


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
    badge_number = fields.Char('Badge Number')
    worker_id = fields.Integer('Worker Number')
    email = fields.Char('Email')

    # ===================================================================
    # HELPER METHODS - Reusable utility functions
    # ===================================================================

    def _extract_ldap_attribute(self, attrs, key, default=''):
        """Helper to safely extract LDAP attributes"""
        if not isinstance(attrs, dict):
            return default
        val = attrs.get(key, [b''])[0] if attrs.get(key) else b''
        return val.decode('utf-8') if isinstance(val, bytes) else default

    def _is_user_in_odoo_group(self, member_of_list):
        """Check if user is member of any group containing 'odoo'"""
        if not member_of_list:
            return False

        for group_dn in member_of_list:
            group_dn_str = group_dn.decode('utf-8') if isinstance(group_dn, bytes) else group_dn
            if 'CN=odoo' in group_dn_str.upper():
                return True
        return False

    def _is_user_in_disabled_ou(self, attrs):
        """Check if user is in disabled OU"""
        distinguished_name = attrs.get('distinguishedName', [])
        if not distinguished_name:
            return False

        dn_str = distinguished_name[0]
        dn_str = dn_str.decode('utf-8') if isinstance(dn_str, bytes) else dn_str
        dn_str = dn_str.upper()

        return ('OU=DISABLED_AFTER_SEPTEMBER_2025' in dn_str or
                'OU=DISABLED_BEFORE_SEPTEMBER_2025' in dn_str)

    def _validate_employee_id(self, employee_id):
        """Validate employee ID is not placeholder value"""
        if not employee_id:
            return False
        return employee_id.strip().lower() not in ['<not set>', 'not set', '', 'null']

    def _should_process_ldap_user(self, attrs):
        """Central validation for whether to process an LDAP user"""
        # Check basic validity
        if not attrs or not isinstance(attrs, dict) or 'sAMAccountName' not in attrs:
            return False, "Invalid LDAP entry"

        # Get user login for debugging
        sam_account = attrs.get('sAMAccountName', [])
        login = ""
        if sam_account:
            login = sam_account[0].decode('utf-8') if isinstance(sam_account[0], bytes) else sam_account[0]

        # Check group membership - use direct logic instead of helper function
        member_of = attrs.get('memberOf', [])


        if member_of:
            # Log first few groups for debugging
            for i, group_dn in enumerate(member_of[:3]):
                group_str = group_dn.decode('utf-8') if isinstance(group_dn, bytes) else group_dn


        # Direct check for odoo group membership (replace helper function)
        target_group = "CN=odoo,CN=Builtin,DC=autocontrole,DC=be"
        is_in_odoo_group = False
        for group_dn in member_of:
            group_dn_str = group_dn.decode('utf-8') if isinstance(group_dn, bytes) else group_dn
            if group_dn_str == target_group:
                is_in_odoo_group = True

                break


        if not is_in_odoo_group:
            return False, "Not member of odoo group"

        # Check disabled OU
        if self._is_user_in_disabled_ou(attrs):
            return False, "User in disabled OU"

        # Check employee ID
        employee_id_raw = attrs.get('employeeID', [])


        if employee_id_raw:
            employee_id = employee_id_raw[0]
            employee_id = employee_id.decode('utf-8') if isinstance(employee_id, bytes) else employee_id


            if not self._validate_employee_id(employee_id):
                return False, "Invalid employee ID"

        return True, "Valid user"

    def _prepare_user_values(self, ldap_attrs, login):
        """Prepare user values dictionary from LDAP attributes"""
        # Extract user data
        display_name = self._extract_ldap_attribute(ldap_attrs, 'displayName')
        badge_number = self._extract_ldap_attribute(ldap_attrs, 'employeeID')
        worker_id = self._extract_ldap_attribute(ldap_attrs, 'employeeNumber')
        email = self._extract_ldap_attribute(ldap_attrs, 'userPrincipalName')
        ldap_login = self._extract_ldap_attribute(ldap_attrs, 'sAMAccountName')

        # Use the login from LDAP if available, otherwise use the passed login
        if not ldap_login:
            ldap_login = login

        # Get the default company
        company = self.env.company or self.env['res.company'].sudo().search([], limit=1)

        return {
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

    def _find_existing_user(self, login, worker_id=None):
        """Find existing user by worker_id or login"""
        user = None

        # First try by worker_id if available
        if worker_id and str(worker_id).isdigit():
            worker_id_int = int(worker_id)
            user = self.search([('worker_id', '=', worker_id_int)], limit=1)

        # Fallback to login if not found
        if not user:
            user = self.search([('login', '=', login)], limit=1)

        return user

    def _get_sync_context(self, for_cron=False):
        """Get appropriate context for user sync operations"""
        base_context = {
            'mail_notrack': True,
            'tracking_disable': True,
            'no_login_notification': True,
            'skip_password_notification': True,
            'no_reset_password': True,
        }

        if for_cron:
            base_context.update({
                'mail_create_nosubscribe': True,
                'mail_create_nolog': True,
            })

        return base_context

    # ===================================================================
    # USER SYNCHRONIZATION METHODS
    # ===================================================================

    def _sync_ldap_user(self, ldap_attrs, login):
        """Sync user data from LDAP attributes"""
        _logger.info(f"Syncing LDAP user: {login}")

        # Early validation
        if not isinstance(ldap_attrs, dict):
            _logger.error(f"[LDAP] Expected dict for ldap_attrs, got {type(ldap_attrs)}: {ldap_attrs}")
            return None

        # Prepare user values
        user_vals = self._prepare_user_values(ldap_attrs, login)
        member_of = ldap_attrs.get('memberOf', [])

        # Find existing user
        worker_id = self._extract_ldap_attribute(ldap_attrs, 'employeeNumber')
        user = self._find_existing_user(login, worker_id)

        if not user:
            return self._create_new_ldap_user(user_vals, member_of)
        else:
            return self._update_existing_ldap_user(user, user_vals, member_of, login)

    def _create_new_ldap_user(self, user_vals, member_of):
        """Create new LDAP user"""
        _logger.info(f"Creating new user for {user_vals['login']}")

        # Add default group for new users
        user_vals['groups_id'] = [(6, 0, [self.env.ref('base.group_user').id])]

        try:
            context = self._get_sync_context(for_cron=False)
            user = self.sudo().with_context(**context).create(user_vals)
            _logger.info(f"Created new LDAP user: {user_vals['login']} with ID: {user.id}")

            self._sync_user_groups(user, member_of)
            return user.id
        except Exception as e:
            _logger.error(f"Failed to create user {user_vals['login']}: {e}")
            return False

    def _update_existing_ldap_user(self, user, user_vals, member_of, login):
        """Update existing LDAP user"""
        _logger.info(f"Updating existing user {login}")

        try:
            context = self._get_sync_context(for_cron=False)
            user_with_context = user.sudo().with_context(**context)
            user_with_context.write(user_vals)
            _logger.info(f"Updated LDAP user: {login}")

            self._sync_user_groups(user_with_context, member_of)
            return user.id
        except Exception as e:
            _logger.error(f"Failed to update user {login}: {e}")
            return user.id

    def _sync_user_groups(self, user, member_of_list):
        """Sync user groups from LDAP"""
        _logger.debug(f"Syncing groups for user: {user.login}")

        # Get odoo groups from LDAP
        connector = self.env['base_act.ldap.connector']
        odoo_group_names = connector.get_odoo_groups_from_ldap(member_of_list)

        # Get or create group category for LDAP groups
        category = self._get_or_create_ldap_category()

        # Remove user from all LDAP-managed groups
        self._remove_user_from_ldap_groups(user, category)

        # Add user to current LDAP groups
        self._add_user_to_ldap_groups(user, odoo_group_names, category)

    def _get_or_create_ldap_category(self):
        """Get or create LDAP group category"""
        category = self.env['ir.module.category'].search(
            [('name', '=', 'LDAP Groups')], limit=1
        )
        if not category:
            category = self.env['ir.module.category'].create({
                'name': 'LDAP Groups',
                'description': 'Groups synchronized from LDAP'
            })
        return category

    def _remove_user_from_ldap_groups(self, user, category):
        """Remove user from all LDAP-managed groups"""
        ldap_groups = self.env['res.groups'].search([
            ('name', '=like', 'odoo_%'),
            ('category_id', '=', category.id)
        ])
        user.groups_id = [(3, g.id) for g in ldap_groups]

    def _add_user_to_ldap_groups(self, user, group_names, category):
        """Add user to LDAP groups"""
        for group_name in group_names:
            group = self._get_or_create_ldap_group(group_name, category)
            if group:
                user.groups_id = [(4, group.id)]

    def _get_or_create_ldap_group(self, group_name, category):
        """Get or create LDAP group"""
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

        return group

    # ===================================================================
    # CRON JOB METHODS
    # ===================================================================

    @api.model
    def cron_sync_ldap_users_with_employee_id(self):
        """CRON job to sync LDAP users with employeeId using existing auth process"""
        _logger.info("Starting LDAP user sync for users with employeeId")

        # Check if LDAP is enabled
        if not self._is_ldap_enabled():
            _logger.info("LDAP not enabled, skipping sync")
            return

        # Initialize statistics
        stats = {
            'users_synced': 0,
            'users_created': 0,
            'users_updated': 0,
            'disabled_ou_filtered': 0,
            'non_odoo_group_filtered': 0,
            'invalid_employee_id_filtered': 0,
        }

        try:
            # Get LDAP entries
            ldap_entries = self._get_ldap_users_for_sync()

            # Process each entry
            for entry in ldap_entries:
                self._process_ldap_entry_for_sync(entry, stats)

            self.env.cr.commit()
            self._log_sync_results(stats)

        except Exception as e:
            _logger.error(f"CRON LDAP sync error: {str(e)}")
            self.env.cr.rollback()

    def _is_ldap_enabled(self):
        """Check if LDAP is enabled"""
        ICP = self.env['ir.config_parameter'].sudo()
        return ICP.get_param('base_act.ldap_enabled', 'False') == 'True'

    def _get_ldap_users_for_sync(self):
        """Get all LDAP users for synchronization"""
        connector = self.env['base_act.ldap.connector']

        with connector.ldap_connection() as conn:
            search_filter = "(&(objectClass=user)(sAMAccountName=*))"
            config = connector.get_ldap_config()
            results = conn.search_s(
                config['base_dn'],
                ldap.SCOPE_SUBTREE,
                search_filter,
                ['sAMAccountName', 'displayName', 'mail', 'memberOf',
                 'userPrincipalName', 'employeeID', 'employeeNumber', 'distinguishedName']
            )


            # Debug first few entries
            return results

    def _process_ldap_entry_for_sync(self, entry, stats):
        """Process a single LDAP entry for synchronization"""
        # Skip invalid entries and referrals
        if not isinstance(entry, tuple) or len(entry) != 2:
            return

        dn, attrs = entry

        # Basic validation
        if not (attrs and isinstance(attrs, dict)):
            return

        sam_account = attrs.get('sAMAccountName', [])
        if not sam_account:
            return

        login = sam_account[0].decode('utf-8') if isinstance(sam_account[0], bytes) else sam_account[0]

        # Validate user should be processed
        should_process, reason = self._should_process_ldap_user(attrs)

        if not should_process:
            self._update_filter_stats(stats, reason)
            return

        # Extract login information
        login_raw = attrs.get('sAMAccountName', [])
        if not login_raw:
            return

        login = login_raw[0]
        login = login.decode('utf-8') if isinstance(login, bytes) else login

        try:
            # Extract worker number for user matching
            employee_number = self._extract_ldap_attribute(attrs, 'employeeNumber')
            employee_number = int(employee_number) if employee_number and employee_number.isdigit() else None

            # Find existing user
            existing_user = self._find_existing_user(login, employee_number)

            if existing_user:
                # Update existing user
                context = self._get_sync_context(for_cron=True)
                existing_user.sudo().with_context(**context)._sync_ldap_user(attrs, login)
                stats['users_updated'] += 1
                _logger.info(f"Updated LDAP user: {login}")
            else:
                # Create new user
                context = self._get_sync_context(for_cron=True)
                result = self.sudo().with_context(**context)._sync_ldap_user(attrs, login)
                if result:
                    stats['users_created'] += 1
                    _logger.info(f"Created LDAP user: {login}")

            stats['users_synced'] += 1

        except Exception as user_error:
            _logger.error(f"Failed to sync user {login}: {str(user_error)}")

    def _update_filter_stats(self, stats, reason):
        """Update filtering statistics based on reason"""
        if "disabled OU" in reason:
            stats['disabled_ou_filtered'] += 1
        elif "not member of odoo group" in reason:
            stats['non_odoo_group_filtered'] += 1
        elif "Invalid employee ID" in reason:
            stats['invalid_employee_id_filtered'] += 1

    def _log_sync_results(self, stats):
        """Log synchronization results"""
        _logger.info(
            f"LDAP sync completed: {stats['users_synced']} total, "
            f"{stats['users_created']} created, {stats['users_updated']} updated. "
            f"Filtered: {stats['disabled_ou_filtered']} disabled OU, "
            f"{stats['non_odoo_group_filtered']} non-odoo group, "
            f"{stats['invalid_employee_id_filtered']} invalid employee ID"
        )