# -*- coding: utf-8 -*-
from odoo import models, api, fields, SUPERUSER_ID
from odoo.exceptions import AccessDenied
import logging
import secrets
import datetime

_logger = logging.getLogger(__name__)


class ResUsers(models.Model):
    _name = 'res.users'
    _inherit = ['res.users', 'base_act.ldap.users']

    tag_auth_token = fields.Char('Tag Auth Token', copy=False)
    tag_auth_expiry = fields.Datetime('Tag Auth Expiry', copy=False)
    department_ids = fields.Many2many('base_act.department', string='Department')

    is_direction_user = fields.Boolean(
        'Is Direction User',
        compute='_compute_is_direction_user',
        store=True
    )

    @api.depends('department_ids')
    def _compute_is_direction_user(self):
        for user in self:
            user.is_direction_user = any(
                'direction' in dept.name.lower()
                for dept in user.department_ids
            )

    @classmethod
    def authenticate(cls, db, credential, user_agent_env):
        """Override authenticate to handle tag-based and LDAP authentication

        This is the main entry point for authentication. It routes to:
        - Tag authentication (passwordless via RFID/NFC)
        - LDAP authentication (with optional domain suffix)
        - Standard Odoo authentication (fallback)
        """
        login = credential.get('login')
        password = credential.get('password')
        credential_type = credential.get('type')

        _logger.debug(f"[AUTH] Authenticate called - login: {login}, type: {credential_type}")

        # Route 1: Tag authentication (pre-validated via service account)
        if credential_type == 'tag_authenticated' and credential.get('tag_validated'):
            return cls._authenticate_tag_user(credential)

        # Route 2: LDAP authentication (normalize login and try LDAP)
        normalized_login = cls._normalize_login(login)

        with cls.pool.cursor() as cr:
            env = api.Environment(cr, SUPERUSER_ID, {})
            ldap_enabled = env['ir.config_parameter'].sudo().get_param('base_act.ldap_enabled', 'False') == 'True'

            if ldap_enabled and normalized_login and password:
                ldap_result = cls._authenticate_ldap_user(env, normalized_login, password, cr)
                if ldap_result:
                    return ldap_result

        # Route 3: Standard Odoo authentication (fallback)
        # Normalize credential for standard auth too (allows admin@domain.com to work)
        if normalized_login != login:
            credential = credential.copy()
            credential['login'] = normalized_login

        return super(ResUsers, cls).authenticate(db, credential, user_agent_env)

    @classmethod
    def _normalize_login(cls, login):
        """Normalize login by stripping domain suffix

        Examples:
            pdra@autocontrole.be -> pdra
            pdra -> pdra
            admin@company.com -> admin
        """
        if login and '@' in login:
            normalized = login.split('@')[0]
            _logger.debug(f"[AUTH] Normalized login from '{login}' to '{normalized}'")
            return normalized
        return login

    @classmethod
    def _authenticate_tag_user(cls, credential):
        """Handle tag-based authentication (passwordless)

        Tag authentication uses a pre-validated credential from the controller.
        The user's status was already verified via LDAP service account.
        """
        login = credential.get('login')
        uid = credential.get('uid')

        _logger.info(f"[TAG-AUTH] Processing pre-validated tag authentication for: {login}")

        if uid:
            return {
                'uid': uid,
                'auth_method': 'tag',
                'mfa': 'default'
            }
        return None

    @classmethod
    def _authenticate_ldap_user(cls, env, login, password, cr):
        """Handle LDAP authentication for existing users only

        Args:
            env: Odoo environment with SUPERUSER_ID
            login: Normalized login (without domain)
            password: User password
            cr: Database cursor

        Returns:
            auth_info dict if successful, None otherwise

        Note:
            Users must be created manually or via LDAP sync.
            This method will NOT auto-create users from LDAP.
        """
        try:
            Users = env['res.users']
            user = Users.search([('login', '=', login)], limit=1)

            if not user:
                # User doesn't exist in Odoo - do NOT auto-create
                _logger.debug(f"[LDAP] User not found in Odoo: {login}")
                return None

            if not user.is_ldap_user:
                # User exists but is not an LDAP user - let standard auth handle it
                _logger.debug(f"[LDAP] User exists but is not an LDAP user: {login}")
                return None

            # User exists and is an LDAP user - authenticate
            return cls._authenticate_existing_ldap_user(env, user, login, password, cr)

        except AccessDenied:
            raise
        except Exception as e:
            _logger.error(f"[LDAP] Error during authentication: {e}")
            import traceback
            _logger.error(traceback.format_exc())
            return None

    @classmethod
    def _authenticate_existing_ldap_user(cls, env, user, login, password, cr):
        """Authenticate an existing LDAP user

        Steps:
            1. Validate credentials against LDAP
            2. Sync user data from LDAP
            3. Return auth_info
        """
        _logger.debug(f"[LDAP] Existing LDAP user found: {login}")

        connector = env['base_act.ldap.connector']
        ldap_attrs = connector.authenticate_user(login, password)

        if not ldap_attrs:
            _logger.warning(f"[LDAP] LDAP authentication failed for existing user")
            raise AccessDenied("Invalid LDAP credentials")

        _logger.debug(f"[LDAP] LDAP authentication successful")

        # Sync user data from LDAP
        user._sync_ldap_user(ldap_attrs, login)
        cr.commit()

        return {
            'uid': user.id,
            'auth_method': 'ldap',
            'mfa': 'default'
        }

    def _check_credentials(self, password, user_agent_env):
        """Check credentials - handle tag auth and LDAP"""
        _logger.debug(f"[DEBUG] _check_credentials called for user: {self.login}")

        # Extract password from dict if needed
        actual_password = password
        if isinstance(password, dict):
            credential_type = password.get('type')

            # If this is tag authentication that was pre-validated, skip all checks
            if credential_type == 'tag_authenticated' and password.get('tag_validated'):
                _logger.info(f"[TAG-AUTH] Skipping credential check - user was pre-validated via tag")
                return  # Success - bypass all password/LDAP checks

            actual_password = password.get('password', '')

        # For LDAP users with password authentication
        ICP = self.env['ir.config_parameter'].sudo()
        ldap_enabled = ICP.get_param('base_act.ldap_enabled', 'False') == 'True'

        if ldap_enabled and self.is_ldap_user:
            _logger.debug(f"[DEBUG] Using LDAP authentication for: {self.login}")

            try:
                connector = self.env['base_act.ldap.connector']
                ldap_attrs = connector.authenticate_user(self.login, actual_password)
                if ldap_attrs:
                    _logger.debug(f"[DEBUG] LDAP authentication successful")
                    self.sudo()._sync_ldap_user(ldap_attrs, self.login)
                    return  # Success
                else:
                    _logger.debug(f"[DEBUG] LDAP authentication failed")
                    raise AccessDenied("Invalid LDAP credentials")
            except AccessDenied:
                raise
            except Exception as e:
                _logger.error(f"[DEBUG] Error during LDAP auth: {e}")
                raise AccessDenied("LDAP authentication error")

        # Fallback to standard authentication for non-LDAP users
        _logger.debug(f"[DEBUG] Using standard Odoo authentication")
        return super()._check_credentials(password, user_agent_env)

    @property
    def is_direction_member(self):
        """Check if user belongs to direction department"""
        direction_dept = self.env.ref('base_act.department_direction', raise_if_not_found=False)
        return direction_dept and self.department_id == direction_dept