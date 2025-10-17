# -*- coding: utf-8 -*-

from odoo import http, _, fields, api
from odoo.http import request
from odoo.addons.web.controllers.home import Home
import datetime
import json
import logging
import secrets


_logger = logging.getLogger(__name__)


class LoginController(Home):

    @http.route('/web/login', type='http', auth="none", website=True, sitemap=False)
    def web_login(self, redirect=None, **kw):
        """Override login to add tag authentication option"""

        # Handle tag authentication if submitted
        if request.httprequest.method == 'POST' and kw.get('auth_method') == 'tag':
            tag_number = kw.get('tag_number', '').strip()

            if tag_number and tag_number.isdigit():
                try:
                    # Search for users with this tag
                    connector = request.env['base_act.ldap.connector'].sudo()
                    matching_users = connector.search_users_by_tag(tag_number)


                    if len(matching_users) == 1:
                        # Single user found - authenticate directly
                        dn, attrs = matching_users[0]
                        login = attrs.get('sAMAccountName', [b''])[0].decode('utf-8')
                        # Auto-login with tag (create session without password)
                        return self._process_tag_login(login, attrs, redirect)

                    elif len(matching_users) == 0:
                        _logger.warning(f"Tag authentication failed: No user found for tag {tag_number}")
                        error_message = "Invalid tag number. Please check your tag or use password login."
                        return request.redirect(f'/web/login?error={error_message}&auth_method=tag')

                    else:
                        # Multiple users found - this shouldn't happen but let's handle it
                        _logger.warning(f"Tag authentication: Multiple users found for tag {tag_number}")
                        error_message = "Multiple users found for this tag. Please contact your administrator."
                        return request.redirect(f'/web/login?error={error_message}&auth_method=tag')

                except Exception as e:
                    _logger.error(f"Tag authentication error: {e}")
                    values = request.params.copy()
                    values['error'] = _(
                        "Authentication system temporarily unavailable. Please try password login or contact support.")
                    return request.render('web.login', values)
            else:
                _logger.warning(f"Tag authentication failed: Invalid tag format '{tag_number}'")
                values = request.params.copy()
                values['error'] = _("Invalid tag format. Please scan a valid tag or use password login.")
                return request.render('web.login', values)

        # Default login page with auth method selector
        response = super().web_login(redirect, **kw)

        return response

    # Replace the _process_tag_login method in controller/main.py

    def _process_tag_login(self, login, ldap_attrs, redirect=None):
        """Process login for tag-authenticated user - simplified approach"""
        _logger.info(f"[TAG-AUTH] Processing tag login for: {login}")

        try:
            # Step 1: Validate user using service account (no password needed)
            connector = request.env['base_act.ldap.connector'].sudo()
            validated_attrs = connector.validate_user_for_tag_auth(login)

            if not validated_attrs:
                error_message = "Your tag access has been disabled or your account is inactive. Please contact your system administrator."
                return request.redirect(f'/web/login?error={error_message}&auth_method=tag')

            # Step 2: Create or sync user (using service account validation)
            users = request.env['res.users'].sudo()
            user = users.search([('login', '=', login)], limit=1)

            is_new_user = not user

            if user:
                _logger.info(f"[TAG-AUTH] Updating existing user: {login}")
                user._sync_ldap_user(validated_attrs, login)
            else:
                _logger.info(f"[TAG-AUTH] Creating new user: {login}")
                user = users._sync_ldap_user(validated_attrs, login)


            request.env.cr.commit()

            if is_new_user:
                try:
                    _logger.info(f"[TAG-AUTH] Setting up permissions for new user: {login}")
                    ldap_users = request.env['base_act.ldap.users'].sudo()

                    ldap_users._setup_ldap_module_permissions()
                    request.env['ldap.permission.manager'].sudo().setup_cross_module_permissions()

                    request.env.cr.commit()
                    _logger.info(f"[TAG-AUTH] Permissions setup completed for user: {login}")

                except Exception as perm_error:
                    # Don't block login, but log the error
                    # The CRON job will fix permissions later if this fails
                    _logger.error(f"[TAG-AUTH] Failed to setup permissions for user {login}: {perm_error}")


            if not user:
                error_message = "Failed to create user account. Please contact your system administrator."
                return request.redirect(f'/web/login?error={error_message}&auth_method=tag')

            # Step 3: Create authenticated session directly (certificate-like auth)
            # This is the key difference - we create the session without password validation
            user_id = user.id if hasattr(user, 'id') else user

            try:
                credential = {
                    'type': 'tag_authenticated',
                    'login': login,
                    'uid': user_id,
                    'tag_validated': True  # This tells authenticate() it's pre-validated
                }

                # This will call our modified authenticate() method
                session_uid = request.session.authenticate(request.db, credential)

                if session_uid:
                    _logger.info(f"[TAG-AUTH] Session created successfully for: {login} (uid: {session_uid})")
                    return request.redirect(redirect or '/web')
                else:
                    _logger.error(f"[TAG-AUTH] Session creation failed for: {login}")
                    error_message = "Failed to create session. Please contact support."
                    return request.redirect(f'/web/login?error={error_message}&auth_method=tag')

            except Exception as session_error:
                _logger.error(f"[TAG-AUTH] Session authentication error: {session_error}")
                error_message = "Session creation failed. Please contact support."
                return request.redirect(f'/web/login?error={error_message}&auth_method=tag')

        except Exception as e:
            _logger.error(f"[TAG-AUTH] Authentication failed: {e}")
            request.env.cr.rollback()
            error_message = "Authentication system error. Please try again or contact support."
            return request.redirect(f'/web/login?error={error_message}&auth_method=tag')