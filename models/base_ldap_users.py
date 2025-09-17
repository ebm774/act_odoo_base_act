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
    # email = fields.Char('Email')

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

        #check if odoo match LDAP :
        needs_user_update = self._check_user_fields_changed(user, user_vals)
        needs_group_update = self._check_user_groups_changed(user, member_of)

        if not needs_user_update and not needs_group_update:
            _logger.debug(f"No changes needed for user {login}")
            return user.id

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

    def _check_user_fields_changed(self, user, user_vals):
        """Check if user record fields need updating by comparing current vs new values"""

        # Fields to compare (excluding relational fields like groups_id)
        fields_to_check = ['name', 'email', 'badge_number', 'worker_id', 'ldap_uid']

        for field in fields_to_check:
            if field not in user_vals:
                continue

            current_value = getattr(user, field, None)
            new_value = user_vals[field]

            # Normalize values for comparison
            if field == 'worker_id':
                # Both should be integers
                current_int = int(current_value) if current_value and str(current_value).isdigit() else 0
                new_int = int(new_value) if new_value and str(new_value).isdigit() else 0
                if current_int != new_int:
                    _logger.debug(f"Field {field} changed: {current_int} → {new_int}")
                    return True

            elif field == 'badge_number':
                # Badge number could be integer or string
                current_val = str(current_value) if current_value not in [None, False, 0, '0'] else ''
                new_val = str(new_value) if new_value not in [None, False, 0, '0'] else ''
                if current_val != new_val:
                    _logger.debug(f"Field {field} changed: '{current_val}' → '{new_val}'")
                    return True

            elif field == 'email':
                # Email comparison should be case-insensitive and trimmed
                current_email = (current_value or '').strip().lower()
                new_email = (new_value or '').strip().lower()
                if current_email != new_email:
                    _logger.debug(f"Field {field} changed: '{current_email}' → '{new_email}'")
                    return True

            else:
                # Generic string comparison for name and ldap_uid
                # Handle None, False, and empty string as equivalent
                current_str = str(current_value).strip() if current_value not in [None, False, ''] else ''
                new_str = str(new_value).strip() if new_value not in [None, False, ''] else ''

                # Avoid comparing 'False' or 'None' as strings
                if current_value is False or current_value is None:
                    current_str = ''
                if new_value is False or new_value is None:
                    new_str = ''

                if current_str != new_str:
                    _logger.debug(f"Field {field} changed: '{current_str}' → '{new_str}'")
                    return True

        _logger.debug(f"No field changes detected for user {user.login}")
        return False

    def _check_user_groups_changed(self, user, member_of_list):
        """Check if user's LDAP groups need updating"""

        # Get current LDAP group names for this user
        ldap_category = self._get_or_create_ldap_category()
        current_ldap_groups = user.groups_id.filtered(
            lambda g: g.category_id.id == ldap_category.id
        ).mapped('name')

        # Get target LDAP group names from LDAP
        connector = self.env['base_act.ldap.connector']
        target_ldap_groups = connector.get_odoo_groups_from_ldap(member_of_list)

        # Compare sets
        current_set = set(current_ldap_groups)
        target_set = set(target_ldap_groups)

        if current_set != target_set:
            added = target_set - current_set
            removed = current_set - target_set
            _logger.debug(f"Group changes for {user.login}: +{added}, -{removed}")
            return True

        _logger.debug(f"No group changes needed for user {user.login}")
        return False

    def _sync_user_groups(self, user, member_of_list):
        """Sync user groups from LDAP with automatic group creation"""
        _logger.debug(f"Syncing groups for user: {user.login}")

        # Get or create group category for LDAP groups
        category = self._get_or_create_ldap_category()

        # Get LDAP groups starting with odoo_
        connector = self.env['base_act.ldap.connector']
        odoo_group_names = connector.get_odoo_groups_from_ldap(member_of_list)

        # Remove user from all LDAP-managed groups first
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
            _logger.info("Created LDAP Groups category")
        return category

    def _remove_user_from_ldap_groups(self, user, category):
        """Remove user from all LDAP-managed groups"""
        ldap_groups = self.env['res.groups'].search([
            ('category_id', '=', category.id)
        ])
        for group in ldap_groups:
            user.groups_id = [(3, group.id)]
        _logger.debug(f"Removed user {user.login} from {len(ldap_groups)} LDAP groups")

    def _add_user_to_ldap_groups(self, user, group_names, category):
        """Add user to LDAP groups, creating them if necessary"""
        added_groups = []
        department_names = []

        for group_name in group_names:
            if group_name.endswith('_department'):
                department_names.append(group_name)
            else:
                group = self._get_or_create_ldap_group(group_name, category)
                if group:
                    user.groups_id = [(4, group.id)]
                    added_groups.append(group_name)

        # Handle department assignments separately
        if department_names:
            self._sync_user_departments(user, department_names, category)
            added_groups.extend(department_names)

        if added_groups:
            _logger.info(f"Added user {user.login} to groups: {', '.join(added_groups)}")

    def _sync_user_departments(self, user, department_names, category):
        """Sync user department assignments and populate Many2many table"""
        try:
            # Clear existing department assignments
            user.department_ids = [(5, 0, 0)]  # Remove all departments from user

            # Add user to new departments
            department_ids = []
            for dept_name in department_names:
                department = self._get_or_create_ldap_department(dept_name, category)
                if department:
                    department_ids.append(department.id)
                    _logger.info(f"Adding user {user.login} to department: {dept_name}")

            # Assign all departments at once
            if department_ids:
                user.department_ids = [(6, 0, department_ids)]
                _logger.info(f"Assigned user {user.login} to {len(department_ids)} departments")

        except Exception as e:
            _logger.error(f"Error syncing departments for user {user.login}: {e}")
            raise

    def _get_or_create_ldap_department(self, group_name, category):
        """Get or create LDAP department with intelligent naming"""
        dept_name = group_name[5:-11] # Remove 'odoo_' and '_department'
        department = self.env['base_act.department'].search([
            ('name', '=', dept_name)
        ], limit=1)

        if not department:

            # Format: odoo_[department_name]_department
            department = self.env['base_act.department'].create({
                'name': dept_name})

        return department

    def _get_or_create_ldap_group(self, group_name, category):
        """Get or create LDAP group with intelligent naming"""
        # First check if group already exists
        group = self.env['res.groups'].search([
            ('name', '=', group_name)
        ], limit=1)

        if not group :
            # Parse group name for better description
            # Format: odoo_[module]_[rights] -> Module: Rights
            parts = group_name.split('_')
            if len(parts) >= 3:
                module_name = parts[1].title()  # Capitalize module name
                rights = '_'.join(parts[2:]).replace('_', ' ').title()

                group_vals = {
                    'name': group_name,
                    'category_id': category.id,
                    'comment': f'LDAP Group: {module_name} - {rights}'
                }

                try:
                    group = self.env['res.groups'].create(group_vals)
                    _logger.info(f"Created LDAP group: {group_name} ({module_name} - {rights})")
                except Exception as e:
                    _logger.error(f"Failed to create group {group_name}: {e}")
                    return None
            else:
                # Fallback for non-standard naming
                try:
                    group = self.env['res.groups'].create({
                        'name': group_name,
                        'category_id': category.id,
                        'comment': f'LDAP Group: {group_name}'
                    })
                    _logger.info(f"Created LDAP group: {group_name}")
                except Exception as e:
                    _logger.error(f"Failed to create group {group_name}: {e}")
                    return None

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

        # STEP 1: Reactivate users moved back from disabled OUs
        try:
            _logger.info("Starting user reactivation check...")
            reactivated_count = self._reactivate_users_moved_from_disabled_ou()
            _logger.info(f"User reactivation completed: {reactivated_count} users reactivated")
        except Exception as e:
            _logger.error(f"Failed to reactivate users: {e}")

        # STEP 2: Normal LDAP sync (now reactivated users will be found as "existing")
        stats = {
            'users_synced': 0,
            'users_created': 0,
            'users_updated': 0,
            'users_skipped': 0,
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

        # STEP 3: Module permissions setup
        try:
            _logger.info("Starting LDAP module permissions setup...")
            self._setup_ldap_module_permissions()
            self.env['ldap.permission.manager'].setup_cross_module_permissions()
            _logger.info("LDAP module permissions setup completed")
        except Exception as e:
            _logger.error(f"Failed to setup module permissions during LDAP sync: {e}")

        # STEP 4: Archive users in disabled OUs
        try:
            _logger.info("Starting disabled OU user cleanup...")
            archived_count = self._archive_disabled_ou_users()
            _logger.info(f"Disabled OU cleanup completed: {archived_count} users archived")
        except Exception as e:
            _logger.error(f"Failed to cleanup disabled OU users: {e}")

    def _reactivate_users_moved_from_disabled_ou(self):
        """Reactivate users who were moved back from disabled OUs and restore their LDAP data"""

        if not self._is_ldap_enabled():
            return 0

        reactivated_count = 0

        try:
            # Find all archived LDAP users
            archived_users = self.env['res.users'].search([
                ('is_ldap_user', '=', True),
                ('active', '=', False),
                ('id', '!=', 1)  # Never touch admin
            ])

            if not archived_users:
                _logger.info("No archived LDAP users to check for reactivation")
                return 0

            _logger.info(
                f"Checking {len(archived_users)} archived users for reactivation: {archived_users.mapped('login')}")

            # Get current LDAP data
            ldap_entries = self._get_ldap_users_for_sync()

            # Process each archived user
            for user in archived_users:
                # Find user's current LDAP data
                user_ldap_data = None
                for entry in ldap_entries:
                    if not isinstance(entry, tuple) or len(entry) != 2:
                        continue

                    dn, attrs = entry
                    if not (attrs and isinstance(attrs, dict)):
                        continue

                    ldap_login = self._extract_ldap_attribute(attrs, 'sAMAccountName')
                    if ldap_login == user.login:
                        user_ldap_data = attrs
                        break

                if not user_ldap_data:
                    _logger.debug(f"Archived user {user.login} not found in LDAP - keeping archived")
                    continue

                # Check if user should be reactivated
                should_process, reason = self._should_process_ldap_user(user_ldap_data)

                if should_process:
                    # User is no longer in disabled OU and meets all criteria
                    try:
                        _logger.info(f"Reactivating user {user.login} - moved from disabled OU")

                        # Step 1: Reactivate the user
                        user.action_unarchive()

                        # Step 2: Sync their LDAP data (groups, departments, etc.)
                        context = self._get_sync_context(for_cron=True)
                        user.sudo().with_context(**context)._sync_ldap_user(user_ldap_data, user.login)

                        reactivated_count += 1
                        _logger.info(f"Successfully reactivated and synced user: {user.login}")

                    except Exception as e:
                        _logger.error(f"Failed to reactivate user {user.login}: {str(e)}")
                else:
                    _logger.debug(f"User {user.login} still should not be active: {reason}")

        except Exception as e:
            _logger.error(f"Error during user reactivation: {str(e)}")
            raise

        return reactivated_count

    def _archive_disabled_ou_users(self):
        """Archive Odoo users who are in disabled OUs in LDAP"""

        if not self._is_ldap_enabled():
            return 0

        archived_count = 0

        try:
            # Reuse your existing LDAP query method
            _logger.info("Querying LDAP for all users to check disabled OUs...")
            ldap_entries = self._get_ldap_users_for_sync()

            if not ldap_entries:
                _logger.info("No LDAP entries returned")
                return 0

            # Find users in disabled OUs from the LDAP results
            disabled_ou_logins = []
            for entry in ldap_entries:
                # Handle the same entry format as your existing code
                if not isinstance(entry, tuple) or len(entry) != 2:
                    continue

                dn, attrs = entry

                # Skip invalid entries
                if not (attrs and isinstance(attrs, dict)):
                    continue

                # Check if user is in disabled OU
                if self._is_user_in_disabled_ou(attrs):
                    login = self._extract_ldap_attribute(attrs, 'sAMAccountName')
                    if login:
                        disabled_ou_logins.append(login)

            if not disabled_ou_logins:
                _logger.info("No users found in disabled OUs")
                return 0

            _logger.info(f"Found {len(disabled_ou_logins)} users in disabled OUs: {disabled_ou_logins}")

            # Find corresponding active Odoo users
            users_to_archive = self.env['res.users'].search([
                ('login', 'in', disabled_ou_logins),
                ('active', '=', True),
                ('id', '!=', 1)  # Never archive admin
            ])

            if users_to_archive:
                _logger.info(
                    f"Archiving {len(users_to_archive)} users from disabled OUs: {users_to_archive.mapped('login')}")

                # Archive them (this terminates sessions automatically)
                users_to_archive.action_archive()

                archived_count = len(users_to_archive)
                _logger.info(f"Successfully archived {archived_count} users from disabled OUs")
            else:
                _logger.info("No active Odoo users found matching disabled OU users")

        except Exception as e:
            _logger.error(f"Error during disabled OU cleanup: {str(e)}")
            raise

        return archived_count

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
                # Check if update is needed
                user_vals = self._prepare_user_values(attrs, login)
                member_of = attrs.get('memberOf', [])

                needs_user_update = self._check_user_fields_changed(existing_user, user_vals)
                needs_group_update = self._check_user_groups_changed(existing_user, member_of)

                if needs_user_update or needs_group_update:
                    # Update existing user
                    context = self._get_sync_context(for_cron=True)
                    existing_user.sudo().with_context(**context)._sync_ldap_user(attrs, login)
                    stats['users_updated'] += 1
                    _logger.info(f"Updated LDAP user: {login}")
                else:
                    # User exists but no changes needed
                    stats['users_skipped'] += 1
                    _logger.debug(f"Skipped LDAP user (no changes): {login}")
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
            f"{stats['users_skipped']} skipped (no changes). "
            f"Filtered: {stats['disabled_ou_filtered']} disabled OU, "
            f"{stats['non_odoo_group_filtered']} non-odoo group, "
            f"{stats['invalid_employee_id_filtered']} invalid employee ID"
        )

    def _setup_ldap_module_permissions(self):
        """Setup module permissions for all LDAP groups following odoo_{module}_user pattern

        Process:
        1. Find all groups matching 'odoo_{module_name}_user'
        2. Extract module name and get first 3 letters
        3. Find all models starting with those 3 letters
        4. Grant full access (except delete) to users in those groups
        """
        _logger.info("Setting up module permissions for LDAP groups...")

        try:
            # Step 1: Get all groups matching the pattern odoo_{module}_user
            ldap_groups = self.env['res.groups'].search([
                ('name', '=like', 'odoo_%_user')
            ])

            _logger.info(f"Found {len(ldap_groups)} LDAP groups matching pattern 'odoo_*_user'")

            for group in ldap_groups:
                self._process_ldap_group_permissions(group)

            _logger.info(f"Completed permission setup for {len(ldap_groups)} LDAP groups")

        except Exception as e:
            _logger.error(f"Failed to setup LDAP module permissions: {e}")

    def _process_ldap_group_permissions(self, group):
        """Process permissions for a single LDAP group"""

        group_name = group.name
        _logger.info(f"Processing permissions for group: {group_name}")

        # Step 2: Extract module name from group name
        module_name = self._extract_module_name_from_group(group_name)
        if not module_name:
            _logger.warning(f"Could not extract module name from group: {group_name}")
            return

        # Step 3: Get first 3 letters of module name
        module_prefix = module_name[:3]
        _logger.info(f"Module '{module_name}' -> searching for models with prefix '{module_prefix}.*'")

        # Step 4: Find all models starting with the 3-letter prefix
        matching_models = self._find_models_by_prefix(module_prefix)

        if not matching_models:
            _logger.warning(f"No models found with prefix '{module_prefix}' for module '{module_name}'")
            return

        # Step 5: Grant permissions to all matching models
        self._grant_permissions_to_models(group, matching_models, module_name)

    def _extract_module_name_from_group(self, group_name):
        """Extract module name from LDAP group name

        Input: 'odoo_order_user' -> Output: 'order'
        Input: 'odoo_inventory_user' -> Output: 'inventory'
        Input: 'odoo_stock_account_user' -> Output: 'stock_account'
        """

        # Check pattern: odoo_{module}_user
        if not group_name.startswith('odoo_') or not group_name.endswith('_user'):
            return None

        # Extract middle part
        parts = group_name.split('_')
        if len(parts) < 3:
            return None

        # Everything between 'odoo_' and '_user'
        module_name = '_'.join(parts[1:-1])

        _logger.debug(f"Extracted module name '{module_name}' from group '{group_name}'")
        return module_name

    def _find_models_by_prefix(self, prefix):
        """Find all Odoo models starting with the given 3-letter prefix

        Args:
            prefix (str): 3-letter prefix (e.g., 'ord', 'sto', 'pur')

        Returns:
            recordset: ir.model records matching the prefix
        """

        # Search for models with pattern: {prefix}.%
        models = self.env['ir.model'].search([
            ('model', '=like', f'{prefix}.%')
        ])

        model_names = models.mapped('model')
        _logger.info(f"Found {len(models)} models with prefix '{prefix}': {model_names}")

        return models

    def _grant_permissions_to_models(self, group, models, module_name):
        """Grant full access (except delete) permissions to group for all models

        Args:
            group (res.groups): The LDAP group
            models (ir.model recordset): Models to grant access to
            module_name (str): Module name for logging
        """

        permissions = (1, 1, 1, 0)  # read, write, create, no delete
        created_rules = 0
        updated_rules = 0

        for model in models:
            try:
                rule_created = self._create_or_update_model_access(group, model, permissions)
                if rule_created:
                    created_rules += 1
                else:
                    updated_rules += 1

            except Exception as e:
                _logger.error(f"Failed to grant permissions for model {model.model} to group {group.name}: {e}")

        _logger.info(
            f"Module '{module_name}' permissions: {created_rules} rules created, {updated_rules} rules updated for group '{group.name}'")

    def _create_or_update_model_access(self, group, model, permissions):
        """Create or update access rule for a specific model and group

        Args:
            group (res.groups): The group to grant access to
            model (ir.model): The model to grant access for
            permissions (tuple): (read, write, create, unlink) permissions

        Returns:
            bool: True if created new rule, False if updated existing
        """

        # Check if access rule already exists
        existing_rule = self.env['ir.model.access'].search([
            ('model_id', '=', model.id),
            ('group_id', '=', group.id)
        ], limit=1)

        # Prepare rule data
        rule_vals = {
            'name': f'{model.model}.ldap.user',
            'model_id': model.id,
            'group_id': group.id,
            'perm_read': permissions[0],
            'perm_write': permissions[1],
            'perm_create': permissions[2],
            'perm_unlink': permissions[3]
        }

        if existing_rule:
            # Update existing rule
            existing_rule.write(rule_vals)
            _logger.debug(f"Updated access rule for {model.model} -> {group.name}")
            return False
        else:
            # Create new rule
            self.env['ir.model.access'].create(rule_vals)
            _logger.debug(f"Created access rule for {model.model} -> {group.name}")
            return True