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

        _logger.error(f"[LDAP] Authenticate called for: {login}")


        # Handle tag authentication (no password required)
        if tag_auth:
            with cls.pool.cursor() as cr:
                env = api.Environment(cr, SUPERUSER_ID, {})
                user = env['res.users'].search([('login', '=', login)])
                if user:
                    _logger.info(f"[AUTH] Tag authentication successful for user: {login}")
                    return {
                        'uid': user.id,
                        'auth_method': 'tag',
                        'mfa': 'default'
                    }

        # Get database cursor
        with cls.pool.cursor() as cr:
            env = api.Environment(cr, SUPERUSER_ID, {})

            # Check if LDAP is enabled
            ICP = env['ir.config_parameter'].sudo()
            ldap_enabled = ICP.get_param('base_act.ldap_enabled', 'False') == 'True'

            if ldap_enabled and login:
                _logger.error(f"[LDAP] LDAP is enabled, checking for user: {login}")
                try:
                    Users = env['res.users']
                    user = Users.search([('login', '=', login)])

                    if not user:
                        # Try to create from LDAP
                        connector = env['base_act.ldap.connector']
                        user_data = connector.search_user(login)
                        if user_data:
                            _logger.error(f"[LDAP] User found in LDAP, creating Odoo user")
                            _, ldap_attrs = user_data
                            # Check if password is valid first
                            if connector.authenticate_user(login, password):
                                users_model = Users.with_user(SUPERUSER_ID)
                                user_id = users_model._sync_ldap_user(ldap_attrs, login)
                                cr.commit()  # Commit the user creation
                                if user_id:
                                    _logger.error(f"[LDAP] Created user with ID: {user_id}")
                                    return {
                                        'uid': user_id,
                                        'auth_method': 'ldap',
                                        'mfa': 'default'
                                    }

                    # If user exists and is LDAP user, try LDAP authentication
                    elif user and user.is_ldap_user:
                        connector = env['base_act.ldap.connector']
                        if connector.authenticate_user(login, password):
                            _logger.error(f"[LDAP] Existing LDAP user authenticated successfully")
                            # Sync user data from LDAP
                            user_data = connector.search_user(login)
                            if user_data:
                                _, ldap_attrs = user_data
                                user._sync_ldap_user(ldap_attrs, login)

                            return {
                                'uid': user.id,
                                'auth_method': 'ldap',
                                'mfa': 'default'
                            }
                        else:
                            _logger.error(f"[LDAP] LDAP authentication failed for existing user")
                            from odoo.exceptions import AccessDenied
                            raise AccessDenied("Invalid LDAP credentials")

                except Exception as e:
                    _logger.error(f"[LDAP] Error during user lookup/creation: {e}")
                    import traceback
                    _logger.error(traceback.format_exc())

        # Continue with normal authentication
        return super(ResUsers, cls).authenticate(db, credential, user_agent_env)

    def _check_credentials(self, password, user_agent_env):
        """Check credentials - try LDAP first for LDAP users"""
        _logger.error(f"[LDAP] _check_credentials for user: {self.login}, is_ldap: {self.is_ldap_user}")

        _logger.error("################################")
        _logger.error(f"[DEBUG] Tag token: {self.tag_auth_token}")
        _logger.error(f"[DEBUG] Tag expiry: {self.tag_auth_expiry}")
        _logger.error(f"[DEBUG] Password received: {password}")
        _logger.error(f"[DEBUG] Password type: {type(password)}")


        # Check tag authentication token first
        if self.tag_auth_token and self.tag_auth_expiry:
            _logger.error(f"[DEBUG] Checking token validity...")
            if fields.Datetime.now() <= self.tag_auth_expiry and password == self.tag_auth_token:
                _logger.info(f"[AUTH] Tag token authentication successful for {self.login}")
                return
            else:
                _logger.error(f"[DEBUG] Token validation failed - expired or mismatch")
        else:
            _logger.error(f"[DEBUG] No tag auth token set")
        _logger.error("################################")

        # Check if LDAP is enabled
        ICP = self.env['ir.config_parameter'].sudo()
        ldap_enabled = ICP.get_param('base_act.ldap_enabled', 'False') == 'True'

        if ldap_enabled and self.is_ldap_user:
            _logger.error(f"[LDAP] User {self.login} is LDAP user, checking LDAP")

            actual_password = password
            if isinstance(password, dict):
                actual_password = password.get('password', '')
                _logger.error(f"[LDAP] Extracted password from dict")

            _logger.error(f"[LDAP] Password type: {type(actual_password)}")

            try:
                connector = self.env['base_act.ldap.connector']
                ldap_attrs = connector.authenticate_user(self.login, actual_password)
                if ldap_attrs:
                    _logger.error(f"[LDAP] LDAP authentication successful")
                    # Update user data from LDAP
                    self.sudo()._sync_ldap_user(ldap_attrs, self.login)
                    return  # Success - no exception = valid
                else:
                    _logger.error(f"[LDAP] LDAP authentication failed")
                    raise AccessDenied("Invalid LDAP credentials")
            except AccessDenied:
                raise
            except Exception as e:
                _logger.error(f"[LDAP] Error during LDAP auth: {e}")
                import traceback
                _logger.error(traceback.format_exc())
                raise AccessDenied("LDAP authentication error")

        # Fallback to standard auth for non-LDAP users
        _logger.error(f"[LDAP] Using standard authentication")
        return super()._check_credentials(password, user_agent_env)