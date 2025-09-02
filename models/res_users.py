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

    @classmethod
    def authenticate(cls, db, credential, user_agent_env):
        """Override authenticate - this is a classmethod!"""
        login = credential.get('login')
        password = credential.get('password')
        tag_auth = credential.get('tag_authenticated', False)

        _logger.debug(f"[AUTH] Authenticate called for: {login}, tag_auth: {tag_auth}")

        # ONLY intercept if it's explicit tag authentication
        if tag_auth:
            _logger.debug(f"[TAG] Processing tag authentication")
            # Tag authentication is handled in controller via manual session setup
            # This path shouldn't normally be reached, but just in case:
            raise AccessDenied("Tag authentication should be handled by controller")

        # For LDAP users, try LDAP authentication first (but don't break normal auth)
        with cls.pool.cursor() as cr:
            env = api.Environment(cr, SUPERUSER_ID, {})

            # Check if LDAP is enabled
            ICP = env['ir.config_parameter'].sudo()
            ldap_enabled = ICP.get_param('base_act.ldap_enabled', 'False') == 'True'

            if ldap_enabled and login:
                try:
                    Users = env['res.users']
                    user = Users.search([('login', '=', login)], limit=1)

                    # If user doesn't exist, try to create from LDAP
                    if not user:
                        connector = env['base_act.ldap.connector']
                        user_data = connector.search_user(login)
                        if user_data:
                            dn, attrs = user_data
                            ldap_attrs = connector.authenticate_user(login, password)
                            if ldap_attrs:
                                _logger.debug(f"[LDAP] Creating new user from LDAP")

                                if not isinstance(ldap_attrs, dict):
                                    _logger.error(f"[LDAP] Expected dict, got {type(ldap_attrs)}: {ldap_attrs}")
                                    raise AccessDenied("LDAP data format error")

                                users_model = Users.with_user(SUPERUSER_ID)
                                user_id = users_model._sync_ldap_user(ldap_attrs, login)
                                cr.commit()
                                if user_id:
                                    return {
                                        'uid': user_id,
                                        'auth_method': 'ldap',
                                        'mfa': 'default'
                                    }
                                else:
                                    _logger.error(f"[LDAP] Failed to create user {login}")
                                    raise AccessDenied("Failed to create LDAP user")
                            else:
                                _logger.error(f"[LDAP] Authentication failed for {login}")
                                raise AccessDenied("Invalid LDAP credentials")
                    elif user.is_ldap_user:
                        connector = env['base_act.ldap.connector']
                        ldap_attrs = connector.authenticate_user(login, password)
                        if ldap_attrs:
                            _logger.debug(f"[LDAP] Existing LDAP user authenticated")
                            user.sudo()._sync_ldap_user(ldap_attrs, login)
                            cr.commit()
                            return {
                                'uid': user.id,
                                'auth_method': 'ldap',
                                'mfa': 'default'
                            }

                except AccessDenied:
                    raise
                except Exception as e:
                    _logger.error(f"[LDAP] Error during LDAP authentication: {e}")
                    # Don't break normal auth for LDAP errors - fall through

        # For all other cases (non-LDAP users, LDAP disabled, etc), use standard Odoo authentication
        return super(ResUsers, cls).authenticate(db, credential, user_agent_env)

    def _check_credentials(self, password, user_agent_env):
        """Check credentials - try LDAP first for LDAP users"""
        _logger.debug(f"[DEBUG] _check_credentials called for user: {self.login}")

        # ✅ EXTRACT PASSWORD FROM DICT IF NEEDED
        actual_password = password
        if isinstance(password, dict):
            actual_password = password.get('password', '')
            _logger.debug(f"[DEBUG] Extracted password from dict")

        _logger.debug(f"[DEBUG] Actual password type: {type(actual_password)}")

        # ✅ FIRST: Check if this is tag authentication with a valid token
        if self.tag_auth_token and self.tag_auth_expiry:
            _logger.debug(f"[DEBUG] Found tag token, checking validity...")
            _logger.debug(f"[DEBUG] Token match: {actual_password == self.tag_auth_token}")

            if fields.Datetime.now() <= self.tag_auth_expiry and actual_password == self.tag_auth_token:
                _logger.info(f"[DEBUG] ✅ TAG AUTHENTICATION SUCCESSFUL - BYPASSING LDAP")
                return  # ✅ SUCCESS - Exit early, don't check LDAP
            else:
                _logger.debug(f"[DEBUG] ❌ Tag token invalid or expired")

        # ✅ SECOND: For non-tag authentication, check LDAP if enabled
        ICP = self.env['ir.config_parameter'].sudo()
        ldap_enabled = ICP.get_param('base_act.ldap_enabled', 'False') == 'True'

        if ldap_enabled and self.is_ldap_user:
            _logger.debug(f"[DEBUG] Proceeding with LDAP authentication")

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

        # ✅ THIRD: Fallback to standard authentication for non-LDAP users
        _logger.debug(f"[DEBUG] Using standard Odoo authentication")
        return super()._check_credentials(password, user_agent_env)