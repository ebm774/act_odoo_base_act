# -*- coding: utf-8 -*-
from odoo import models, api, fields, SUPERUSER_ID
from odoo.exceptions import AccessDenied
import logging
import secrets
import datetime

_logger = logging.getLogger(__name__)


class ResUsers(models.Model):
    _name='res.users'
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
        """Override authenticate to handle tag-based authentication"""
        login = credential.get('login')
        credential_type = credential.get('type')

        _logger.debug(f"[AUTH] Authenticate called - login: {login}, type: {credential_type}")

        # Handle tag-authenticated sessions (certificate-like authentication)
        if credential_type == 'tag_authenticated' and credential.get('tag_validated'):
            _logger.info(f"[TAG-AUTH] Processing pre-validated tag authentication for: {login}")

            # Tag was already validated by controller using service account
            # Just return the user ID - no password checking needed
            uid = credential.get('uid')
            if uid:
                return {
                    'uid': uid,
                    'auth_method': 'tag',
                    'mfa': 'default'
                }

        # For all other authentication (password, LDAP, etc.), use existing logic
        return super(ResUsers, cls).authenticate(db, credential, user_agent_env)

    def _check_credentials(self, password, user_agent_env):
        """Check credentials - handle tag auth and LDAP"""
        _logger.debug(f"[DEBUG] _check_credentials called for user: {self.login}")

        # Extract password from dict if needed (your existing logic)
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

